# 隐藏层「计时侧信道」加固（signal A/B/C/D）

针对一份 KernelSU/SukiSU 隐藏机制侧信道检测报告的内核侧修复。隐藏层改写了
SELinux 查询 / syscall 的**返回值**，却没有抹平产生这些返回值所花的**时间**；
一个普通（无 root）App 靠测量延迟分布，就能把挂了隐藏的内核与干净内核区分开。

本目录 [`apply.sh`](apply.sh) 在 CI 构建流程里（克隆 SukiSU-Nova + 应用
`sukisu_compat` / SUSFS 补丁**之后**）对最终形态的 KSU 源码打补丁，内容检测守卫、
可重复执行幂等。仅对 `ksu_variant == 'SukiSU-Nova'` 生效。

## 四条信号与处理

| 信号 | 位置 | 机理 | 本补丁 |
|---|---|---|---|
| **A** 策略发布竞态 | `kernel/selinux/rules.c`、`kernel/selinux/sepolicy.c` | `apply_kernelsu_rules()` 在 `rcu_assign_pointer()` **之前**就把 `ksu_original_types_*` 切到新代际；整个规则构建窗口内读者是「旧 live 策略 + 新代际元数据」，`ksu_type_is_original()` 返回 -1 → `backup_string_to_context_struct()` 判 `-EAGAIN` → 多走一次回退解析。 | **已修**：元数据发布挪到 `rcu_assign_pointer()` 之后，窗口从「构建规则全程」收敛到两条写指令。见下文。 |
| **B** 无效上下文冗余解析 | `kernel/feature/selinux_hide.c` `string_to_context_struct()` | live 策略的 MLS 解析失败后，仍对 backup(orig) 策略多跑一次 `mls_context_to_sid()` + MLS 后缀 `memcpy`，其结果在 `out:` 处被丢弃。喂畸形 context，被 hook 的内核比干净内核拒绝得更慢。 | **已修**：`if (orig_valid)` → `if (orig_valid && !rc)`。 |
| **C** syscall dispatcher 固定开销 | `kernel/hook/syscall_hook_manager.c` `ksu_sys_enter_handler()` + `kernel/feature/sucompat.c` | `newfstatat`/`faccessat` 高频 syscall 对**所有**进程都被重定向进 KSU dispatcher，再在 sucompat 处理函数里按 allow-uid 提前返回。普通 App 每次都多付一段固定的 dispatcher 往返开销，最适合被动、纯无特权检测。 | **已修**：把 allow-uid 判定上提到 tracepoint，非授权进程走原生快路径。 |
| **D** `attr/current` 换行前缀 vs 非法类型 | `kernel/feature/selinux_hide.c` `my_setprocattr()` | 成对写 `/proc/self/attr/current`：A=非法类型，B=换行前缀，两者都返回 `-EINVAL`。B 在 stock 上走 `prepare_creds()/abort_creds()`，A 在解析内部 early-return，差值 700~800 ns。 | **不改**：上游 PR #3981 已把该路径对齐 stock（保留短路 + 单次解析），main 已含该修复。详见下文。 |

## 已应用的改动

### 信号 A — `kernel/selinux/rules.c`

两处发布点（`apply_kernelsu_rules()` 与 `handle_sepolicy()`）都把 original-types 元数据
从 `rcu_assign_pointer()` 之前移到之后：

```c
    pol->latest_granting = old_pol->latest_granting + 1;
-   if (!ksu_set_original_types(db, &old_pol->policydb, pol->latest_granting))
-       pr_warn("failed to save original type metadata, use backup lookups\n");
    ...
    rcu_assign_pointer(selinux_state.policy, pol);
+   /* KSU_SIDECHAN_A_PUBLISH */
+   if (!ksu_set_original_types(db, &old_pol->policydb, pol->latest_granting))
+       pr_warn("failed to save original type metadata, use backup lookups\n");
    synchronize_rcu();
```

为什么这样就够了：

- 发布前读者拿到旧 live 策略，元数据也仍指向旧 db/旧代际 → `ksu_type_is_original()` 正常返回 1/0。
- 发布后读者拿到新策略，元数据随指针一起切到新 db/新代际 → 仍然 1/0。
- 残留窗口只剩 `rcu_assign_pointer()` 与两次 `WRITE_ONCE` 之间；命中时按既有 `-EAGAIN`
  路径重试一次，与 stock `sidtab_freeze`/`-ESTALE` 重试同构，不再是「毫秒级持续重试」。
- 策略内容、SID 分配、`ksu_type_is_original()` 的 `-1/0/1` 语义、隐藏正确性都不变；
  `old_pol` 在 `synchronize_rcu()` 之前仍然有效，元数据读取 `orig_db->p_types.nprim` 安全。

### 信号 C — `kernel/hook/syscall_hook_manager.c`

补 `#include <linux/cred.h>`、`#include "policy/allowlist.h"`，并在
`ksu_sys_enter_handler()` 里 `current_regs` 声明之后插入门控：

```c
if (id == __NR_newfstatat || id == __NR_faccessat) {
    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return; /* KSU_SIDECHAN_C_GATE: 非授权进程走原生快路径，不进 dispatcher */
}
```

- `ksu_handle_stat_sucompat` / `ksu_handle_faccessat_sucompat` 对非授权 uid 本来就
  `goto do_orig_*` 直接放行，所以这里**结果完全一致**，只是省掉 dispatcher 往返。
- 授权（root）App 行为不变；`setresuid`（需对所有进程可见）、`execve`/`execveat`
  （低频）不门控。
- `__ksu_is_allow_uid_for_current()` 走 `rcu_read_lock` + hash 查找，非睡眠、原子上下文
  安全，且本就在该 syscall 路径里被调用，只是提前了调用点。
- 声明放在 `current_regs` 之后，避免 `-Wdeclaration-after-statement` 在 `-Werror` 下报错。

> 残留：`sys_enter` tracepoint 本身对每个 syscall 都会触发（任何 sys_enter 消费者都如此，
> 非 KSU 独有）。本补丁消除的是 KSU 独有的、每次 `newfstatat`/`faccessat` 的 dispatcher
> 往返开销——也就是报告里 C 信号的主体。

### 信号 B — `kernel/feature/selinux_hide.c`

```c
rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
if (orig_valid && !rc) { /* KSU_SIDECHAN_B_GUARD */   // 原: if (orig_valid) {
    ... 第二次(backup) mls_context_to_sid + MLS 后缀 memcpy ...
}
```

- `rc != 0`（live 解析失败）时，`out:` 本就把 `orig_rc` 强制为 `-EINVAL` 并丢弃 backup
  结果；加 `!rc` 守卫后直接**跳过**这次无用解析，使非法路径与原生内核一样只解析一次。
- 合法路径（`rc == 0`）分支条件等价于原来的 `orig_valid`，**行为完全不变**，隐藏正确性
  不受影响。
- 该文件作者本就在时序上对齐原生（见函数内 "Match native early return…" 注释）；本补丁
  把这一思路补到了 MLS 阶段。

> 残留：本补丁只关闭 MLS 阶段的重复解析。字段阶段的冗余由上游 #3936 处理（一次 pass
> 同查两个策略），attr/current 路径由 #3981 对齐 stock。

### 信号 D — attr/current：**不改**，上游已处理

早前版本曾在这里用「把换行前缀也拽进解析层 + 三字段恒查」把 A/B 拉平。方向是错的，
补丁已移除，保留这段记录：

- **PR #3981** `fix(kernel): parse setprocattr context once in selinux hide`
  （genie1997，2026-11-09 合并）。探针与本目录描述完全一致：A = 40 字节非法类型，
  B = 同长度以换行开头。作者原话："On stock the newline write pays for
  `prepare_creds()`/`abort_creds()` and the invalid type fails well before that."
- 修法：**保留 `str[0] != '\n'` 短路**，解析改成单次 `security_context_to_sid_live()`，
  只在 type mark stale（`-EAGAIN`）时回退 dual parse。
- 实测（4096 对，64×64 批量均值）：

  | A−B | Before | After |
  |---|---|---|
  | CPU0 hooked | −4 / −4 ns | **−864 / −833 ns** |
  | CPU0 stock 路径（同一次开机） | −384 ns | **−776 ns** |
  | CPU4 hooked | +1 / −6 ns | −81 / −78 ns |

`main` 已包含 #3981，所以 `my_setprocattr()` 里
`if (size && str[0] && str[0] != '\n')` **是上游修完的结果，不是遗留缺陷** —— 本脚本
保持这条路径原样，一个字节都不动。

#### 其它相关讨论

| 条目 | 状态 | 内容 |
|---|---|---|
| Issue #3941 | closed | Android 17 / 6.18 + Duck Detector：`+188 ns`、`aSlower 13/16`；无 root 时 16/16 落零块 |
| PR #3938 | **未合并** | 0ctobot：`+78 → −43 ns`、`+105 → −52 ns`；128 字节栈缓冲替掉 `kmemdup`；先验 backup 再碰 live；自述"不保证时序相等" |
| PR #3936 | 已合并 | 字段切分与双策略查找收进一次 pass，MLS 后缀按需还原 |
| PR #3877 | 已合并 | MLS 阶段（本目录信号 B 的同源修复） |
| PR #3965 | open (WIP) | Align policy-load notifications，对应信号 A |

#### 想靠内核侧消除这条检测，走不通

探针对本身不对称：stock 上 B 走 cred 分配、A 在解析里早退，差值 700~800 ns。任何把
A/B 拉平的改动都必然在绝对延迟上与 stock 分叉。判定侧才是正确落点：用同版本 stock
基线的 `z = (A−B − baseline_med) / baseline_iqr`，或换同构探针对。

## 信号 A 的边界与上游对照

信号 A 分两层修完：

1. **发布顺序**（rules.c）：代际元数据不再领先于策略指针。
2. **发布原子性**（sepolicy.c）：`limit` 与 `generation` 压进同一个 `u64`
   （low32=limit，high32=generation）单次发布，`policy` 指针先写。arm64 上对齐 64 位写
   是单次原子，读者拿到的 `(limit, generation)` 永远同代；与 policy 指针错配只会返回
   `-1`（走既有重试）。这同时关掉了旧实现里真实存在的**隐藏绕过**：以前可能读到
   「新 limit + 旧 generation」，一旦代际恰好等于调用方代数，KSU 新增类型会被误判为
   original 而放行。三个函数的对外签名不变，`selinux_hide.c` 无需改动。

仍属「另一种取舍」、没有做的：

- **netlink 可见性**：策略发布仍会向 app 所属的 SELinux netlink socket 广播
   policy-load。上游 [PR #3965](https://github.com/tiann/KernelSU/pull/3965)（open, WIP）
   在做「隐藏生效时过滤 app 收件人」，6.1 因缺 `netlink_broadcast_filtered` 仍是未解决项。
   本仓库不采用该 WIP：它改的是接收路径，牵涉 hook 生命周期与跨版本兼容，且 `selinux_hide`
   的状态页已经是冻结视图，收益与风险不匹配。

## 验证（必须在真机上做）

本补丁**无法在构建期验证时序**。刷入后请用报告的测量方法学复测：

1. **功能回归**：开机正常；管理器可授权；已授权 App `su` 可用；SELinux `enforcing`
   状态与授权行为正常。
2. **信号 C**：无特权 App 对自身 `newfstatat`/`faccessat` 成对计时，对比干净内核的分位数
   分布，应不再有固定偏移。
3. **信号 B**：喂畸形 context 触发 `setxattr`/`context_to_sid` 路径，成对计时对比，失败
   路径应与干净内核一致。
4. **信号 D**：成对写 `/proc/self/attr/current`：A=非法类型、B=换行前缀（等长），各 512 对
   AB/BA 交替、32 次预热。修复后两者都应在解析层返回 `-EINVAL`，方向计数应收敛到
   `3 × (反向 + ties)` 以内，block 分布从 `0/16/0` 变成接近 `8/8/0`。
5. **信号 A**：开机后立即（`apply_kernelsu_rules()` 窗口内）与运行期 `ksud sepolicy` 前后，
   各做一组 `context_to_sid` / `attr/current` 写入的成对计时。修复前窗口内是毫秒级持续
   的 `-EAGAIN` 重解析；修复后应只剩零星的单次重试，尾延迟分布与 stock 同量级。

> 重要：请保留可恢复路径（fastboot 可刷回的 boot/init_boot 备份）。改动涉及 syscall
> 热路径与 SELinux 解析路径，务必先在可恢复的设备上验证再日常使用。
