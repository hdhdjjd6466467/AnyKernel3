# 隐藏层「计时侧信道」加固（signal B/C/D）

针对一份 KernelSU/SukiSU 隐藏机制侧信道检测报告的内核侧修复。隐藏层改写了
SELinux 查询 / syscall 的**返回值**，却没有抹平产生这些返回值所花的**时间**；
一个普通（无 root）App 靠测量延迟分布，就能把挂了隐藏的内核与干净内核区分开。

本目录 [`apply.sh`](apply.sh) 在 CI 构建流程里（克隆 SukiSU-Nova + 应用
`sukisu_compat` / SUSFS 补丁**之后**）对最终形态的 KSU 源码打补丁，内容检测守卫、
可重复执行幂等。仅对 `ksu_variant == 'SukiSU-Nova'` 生效。

## 四条信号与处理

| 信号 | 位置 | 机理 | 本补丁 |
|---|---|---|---|
| **A** 策略发布竞态 | `kernel/selinux/rules.c`、`kernel/selinux/sepolicy.c` | `apply_kernelsu_rules()` 发布新策略时 `latest_granting` 代际推进，live 与 backup 在一个窗口内不一致 → `security_context_to_sid_live()` 返回 `-EAGAIN` → 回退 backup 重解析。重载窗口内出现干净内核没有的瞬态尾延迟/重试。 | **不改**（仅 `::notice` 提示）。见下文。 |
| **B** 无效上下文冗余解析 | `kernel/feature/selinux_hide.c` `string_to_context_struct()` | live 策略的 MLS 解析失败后，仍对 backup(orig) 策略多跑一次 `mls_context_to_sid()` + MLS 后缀 `memcpy`，其结果在 `out:` 处被丢弃。喂畸形 context，被 hook 的内核比干净内核拒绝得更慢。 | **已修**：`if (orig_valid)` → `if (orig_valid && !rc)`。 |
| **C** syscall dispatcher 固定开销 | `kernel/hook/syscall_hook_manager.c` `ksu_sys_enter_handler()` + `kernel/feature/sucompat.c` | `newfstatat`/`faccessat` 高频 syscall 对**所有**进程都被重定向进 KSU dispatcher，再在 sucompat 处理函数里按 allow-uid 提前返回。普通 App 每次都多付一段固定的 dispatcher 往返开销，最适合被动、纯无特权检测。 | **已修**：把 allow-uid 判定上提到 tracepoint，非授权进程走原生快路径。 |
| **D** `attr/current` 失败路径不等时 | `kernel/feature/selinux_hide.c` `my_setprocattr()` / `backup_string_to_context_struct()` / `string_to_context_struct()` | 成对写 `/proc/self/attr/current`：A=非法类型，B=换行前缀，两者都必须返回 `-EINVAL`。B 原生在 `str[0] != '\n'` 处短路，落到 `prepare_creds()/abort_creds()`；A 在解析内部 early-return。两条失败路径差一次 cred 分配/释放，再叠加字段失败深度差，方向计数一边倒。 | **已修**：换行前缀不再短路、三字段恒查、backup 字段查询推迟到 live 全通过之后。 |

## 已应用的改动

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

> 残留：本补丁只关闭 MLS 阶段的重复解析。字段阶段的冗余（每个字段对 live/backup 各查一次，
> 以及首次失败即返回造成的失败深度差）由信号 D 一并处理。

### 信号 D — `kernel/feature/selinux_hide.c`

三条改动，全部只落在失败路径：

1. **`my_setprocattr()`**：`if (size && str[0] && str[0] != '\n')` → `if (size && str[0])`。
   换行开头的输入不再短路到 `prepare_creds()`/`abort_creds()`，而是同样进入解析层。
   返回码仍是 `-EINVAL`（`sid` 保持 0），语义不变。
2. **`backup_string_to_context_struct()`**：user / role / type 三个字段一律查完再判失败，
   失败成本不再取决于首次失败的字段位置。
3. **`string_to_context_struct()`**：同样三字段恒查；并把 backup(orig) 策略的字段查询
   推迟到 live 三字段全部通过之后。live 失败时 orig 结果本来就在 `out:` 被丢弃，推迟
   不改变任何可观察行为；live 成功时查询结果与原先完全一致。

改动前后两条失败路径的成本结构：

| 探针 | 改动前 | 改动后 |
|---|---|---|
| A 非法类型 | perm → kmemdup → user/role 命中、type 失败即 return（2 次命中 + 1 次未命中） | perm → kmemdup → 三字段恒查 → return |
| B 换行前缀 | perm → `prepare_creds()` → `abort_creds()`（0 次查找） | perm → kmemdup → 三字段恒查 → return |

两条路径都终止在解析层、都付相同次数的哈希查找，方向计数不再一边倒。
`string_to_context_struct()`（setxattr 的 dual-parse 入口）同步改造，另外把
backup(orig) 的字段查询整体推迟，使畸形 context 的失败路径不再多付两次查找。

> 这不是「给 B 加延迟」，而是把 B 从 cred 分配路径挪到解析路径，并把 A 的失败深度归一。
> 合法 context（`rc == 0`）的路径与耗时完全不变。
> 字段数不足（缺少 `:`）的输入仍会在切分处早退 —— 这类输入与等长探针对的形态不同，
> 不在成对测量的覆盖范围内。

#### 上游已经修过这条路径（重要）

动手之前先看这段：**tiann/KernelSU 已经处理过同一个探针，而且结论与信号 D 的方向相反。**

- **PR #3981** `fix(kernel): parse setprocattr context once in selinux hide`
  （genie1997，2026-11-09 合并）。描述里的探针与这里完全一致：A = 40 字节非法类型，
  B = 同长度以换行开头。作者原话："On stock the newline write pays for
  `prepare_creds()`/`abort_creds()` and the invalid type fails well before that."
  修法是**恢复 `str[0] != '\n'` 短路 + 单次解析**（`security_context_to_sid_live`），
  只在 type mark stale（`-EAGAIN`）时才回退 dual parse。
- **Issue #3941**（Android 17 / 6.18，Duck Detector）报 `+188 ns`、`aSlower 13/16`；
  **PR #3938**（0ctobot，未合并）给出 `+78 → −43 ns`、`+105 → −52 ns` 对照，并写明
  "reduces avoidable timing overhead without guaranteeing timing equality"。
- **PR #3936**（已合并）把字段切分与双策略查找收进一次 pass；**PR #3877**（已合并）
  处理 MLS 阶段。

`main` 现在已包含 #3981 —— 也就是说 `my_setprocattr()` 里
`if (size && str[0] && str[0] != '\n')` 这行**是上游修完的结果，不是遗留缺陷**。

#### 所以信号 D 默认关闭

信号 D 做的恰好是反方向：把换行前缀也拽进解析层、三字段恒查。那会让 hooked 路径
进一步偏离 stock —— 上游实测 stock 上 B 比 A 慢 700~800 ns，把 B 压到 A 的水平等于
在绝对延迟上自报身份。

| 检测器形态 | 建议 |
|---|---|
| 拿报告里的方向阈值来判 | 先确认内核 `my_setprocattr` 是否已带 `str[0] != '\n'` 短路。带了就别开 D —— 你的 `A<B` 就是 stock 的形状 |
| 确实需要方向差归零 | `SIDECHAN_D=1` 显式打开 |
| 会与同版本编译的 stock 基线比较 | 一律 `SIDECHAN_D=0`（默认） |

真正要"修复"这条检测，落点在判定侧：用 stock 基线校准（`z = (A−B − baseline_med) /
baseline_iqr`），或改用同构的探针对。探针对本身不对称时，方向计数没有判别力。

## 为什么不自动修信号 A

A 的根因是 `apply_kernelsu_rules()` 在 `selinux_state.policy_mutex` 下换策略 + 刷新
backup 时存在一个 live/backup 代际不一致的窗口。要彻底消除需要把「策略换装 + backup
重建 + 代际切换」做成对查询原子可见（RCU 发布顺序 / 代际握手重设计）。这属于启动关键、
SELinux 判定关键路径，**盲改**（无法在本地编译、无法在真机验证的前提下）有开机失败或
安全标签判定错误的风险。因此本脚本只对 A 发 `::notice` 提示，改动留给真机迭代：

- 让 backup 刷新与 live 策略换装在同一 `policy_mutex` 临界区内、以单一代际数对外发布；
- 或在重载窗口内让回退路径与正常路径等时（例如预热 backup sidtab，使 `-EAGAIN` 重解析
  不额外增加可测延迟）。

两种方向都需配合报告里的测量方法学（成对测量、分位数、控混淆项）在真机上判别后再定稿。

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
5. **信号 A**：在 `load_policy` / 策略重载窗口附近高频探测，确认（或量化残留的）瞬态尾延迟。

> 重要：请保留可恢复路径（fastboot 可刷回的 boot/init_boot 备份）。改动涉及 syscall
> 热路径与 SELinux 解析路径，务必先在可恢复的设备上验证再日常使用。
