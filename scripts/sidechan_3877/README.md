# #3877 同源「失败路径时序对齐」

KernelSU-Next v3.4.2 的发布说明里那条

> fix(kernel): fix time side-channel detection in selinux hide (tiann/KernelSU#3877) by @pershoot in #1601

对应到上游就是 **tiann/KernelSU PR #3877**（5ec1cff，2026-10-10 合并，214+/125-，
只动 `kernel/feature/selinux_hide.c`）。本目录把它「消掉冗余工作量」的思路补到
**SukiSU-Nova `builtin` 分支**——也就是 CI 实际构建的那棵树（`kernel-a12-5-10.yml` 等
都走 `BRANCH="builtin"`）。

## 1. 上游 #3877 到底改了什么

三件事，全部围绕「hooked 路径要和 stock 付同样的代价」：

| # | 改动 | 原来 | 现在 |
|---|---|---|---|
| 1 | 去掉**第二次** `security_context_to_sid()` | 先对 backup 策略转一次 SID，再调一次全局 `security_context_to_sid()`（源码注释就叫 `// sync to global sidtab`）把 live sidtab 也补上 | `security_context_to_sid_with_policy(..., u32 *orig_sid_p, int *orig_rc_p)`：**一次 `kmemdup_nul`、一个 `rcu_read_lock()` 段、一次双策略解析 + 两次 `sidtab_context_to_sid()`** |
| 2 | `my_setprocattr()` 回到 stock 形状 | 先转 SID，出错再补一次 `avc_has_perm` 才返回 | `prepare_creds()` → 解析 → `PROCESS__SETCURRENT/DYNTRANSITION/PTRACE` 检查 → `commit_creds()/abort_creds()`，与 `selinux_setprocattr` 同构 |
| 3 | 清理版本分支 | `< 6.6` 用 `struct selinux_state fake_state` 假装一个策略 | 删掉 `fake_state`，补 `6.18` 的 `cred_security_struct` 兼容宏 |

第 1 条是关键：**同一次查询，隐藏着的内核比干净内核多做一遍完整解析。** 返回值一样，
耗时差一倍量级，探针用几万次采样就能把分布分开。这就是「time side-channel in selinux hide」。

## 2. `builtin` 分支还缺什么

`builtin` 已经吃到了第 1 条的骨架（函数签名带 `orig_sid_p`/`orig_rc_p`、live sidtab
同步在同一个 RCU 段内、只有一次 `kmemdup_nul`），但 stock `string_to_context_struct()`
的两处「未知字段立刻返回」没跟上。**失败路径**因此仍比 stock 深：

```c
/* stock: security/selinux/ss/services.c */
usrdatum = symtab_search(&pol->p_users, scontextp);
if (!usrdatum)
        goto out;                 /* 立刻 -EINVAL，后面的字段一个字节都不看 */
ctx->user = usrdatum->value;
```

```c
/* builtin: kernel/feature/selinux_hide.c（打补丁前） */
usrdatum        = symtab_search(&pol->p_users, scontextp);
orig_usrdatum   = symtab_search(&orig_pol->p_users, scontextp);   /* 第 2 次查找 */
if (usrdatum) ctx->user = ...; else live_valid = false;           /* 不返回，继续扫 */
...
```

于是喂 `u:r:<超长 type>:s0` 这类非法 context：

* 干净内核：在 user 字段就 `-EINVAL`；
* 隐藏内核：把 role、type、MLS 后缀整串扫完，中途还多两次 `symtab_search`，
  最后才 `-EINVAL`。

**差值随输入长度增长**——正是 #3877 那一类「返回值一致、耗时不一致」的口子，只不过
落在失败路径而不是成功路径上。

第二处是 attr/current 那一对（报告里信号 D 用的探针）：

```c
/* stock + 上游 main */
if (size && str[0] && str[0] != '\n') {
/* builtin 打补丁前 */
if (size && str[0]) {
```

写单个 `"\n"`：干净内核跳过解析，走 `prepare_creds()`/`abort_creds()` 之后才 `-EINVAL`；
`builtin` 直接进解析层，`size == 0` 立刻 `-EINVAL`，省掉整整一次 cred 分配与回滚。
成对计时（非法类型 vs 换行）因此长期偏向一边。上游 #3981 修的就是这条，`main` 有、
`builtin` 没有——所以本补丁把 `builtin` 拉回同一条形状。

## 3. 补丁内容（`apply.sh`）

| 标记 | 落点 | 改动 |
|---|---|---|
| `KSU_SIDECHAN_3877_FASTFAIL` | `string_to_context_struct()` user / role 两段 | 未知 user / role 直接 `goto out`，orig 侧的 `symtab_search` 移到早退之后（失败路径不再查） |
| `KSU_SIDECHAN_3877_NEWLINE` | `my_setprocattr()` | `if (size && str[0])` → `if (size && str[0] && str[0] != '\n')` |

### 语义等价

* **E**：早退返回的就是原来的 `rc = -EINVAL`；`out:` 处依旧 `context_destroy(ctx)`、
  把 `orig_rc` 强制成 `-EINVAL` 并销毁 `orig_ctx`。**错误码、sid、隐藏判定全不变**，
  只是少扫几段字面量、少两次 `symtab_search`。`live_valid` 仍由 type 分支使用，不会
  变成未使用变量。
* **F**：写 `"\n"` 依旧 `-EINVAL`（`sid == 0` → `abort_change`），只是改走 stock 的
  cred 路径。合法 context 完全不受影响（`str[0]` 不是换行时行为一模一样）。

### 幂等与降级

* 命中标记即跳过；锚点出现次数 ≠ 1 直接报错，不猜。
* `SKIP_INCOMPATIBLE=true` 时降级成 `::warning`，不中断构建。
* 上游若自行把这四处补齐，`sub_once()` 的「锚点 0 次」分支会静默放过，脚本整体仍然
  成功退出（不算失败）。

## 4. 验证

构建期只能证明补丁落地（`grep` 标记），**时序必须在真机上量**：

1. **长度扫描（E）**：无特权 App 循环写 `/proc/self/attr/current`（或 `/sys/fs/selinux/context`）
   喂非法 context，type 字段长度从 8 扫到 512 字节，各 4096 次，取中位数与 IQR。
   修复前应看到中位数随长度单调上升，修复后与干净内核同斜率（≈0）。
2. **成对计时（F）**：A = 40 字节非法类型，B = 等长以换行开头；AB/BA 交替各 512 对，
   32 次预热。修复后两者都走 stock 形状，方向计数应收敛（`3 × (反向 + ties)` 以内），
   block 分布从 `0/16/0` 趋向 `8/8/0`。
3. **功能回归**：开机正常；`su` 可用；`setcon` 类操作的结果与修复前一致（隐藏语义不变）。

> 机器上保留可回滚的 boot / init_boot 备份再刷。

## 5. 与既有补丁的关系

| 目录 | 关系 |
|---|---|
| `sidechan_hide`（A/B/C） | B 处理的是「live 解析失败后仍跑 backup 的 MLS 解析」，属**成功/失败两支**的重复工作；本目录处理的是**字段阶段**的早退差异，两者不重叠，可同时开 |
| `sidechan_equalize` | 改的是 `ksu_type_is_original()` 的三态判定（`-EAGAIN` 回退），本目录不动它 |
| `sidechan_3938` | 实验性的栈缓冲方案（未合并），与本目录互不影响 |
| `avdseqno_fix` | 改 selinuxfs 回复字段，与本目录无关 |

## 6. 回滚

脚本不改 git 历史，只改工作区文件：

```bash
git -C "$KERNEL_ROOT/KernelSU" checkout -- kernel/feature/selinux_hide.c
```

或把 `sidechan_3877` 输入设为 `false` 重新构建。
