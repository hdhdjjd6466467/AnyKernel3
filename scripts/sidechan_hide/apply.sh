#!/usr/bin/env bash
# SukiSU-Nova 隐藏层「计时侧信道」加固补丁
#
# 背景（对应一份针对 KernelSU/SukiSU 隐藏机制的侧信道检测报告）：
#   隐藏层改写了 SELinux 查询 / syscall 的返回值，但没有抹平产生这些返回值
#   所花的时间。一个普通（无 root）App 靠测量延迟分布，就能把挂了隐藏的内核
#   与干净内核区分开。报告定位到三条信号：
#
#     A  策略发布竞态窗口（kernel/selinux/rules.c、kernel/selinux/sepolicy.c）
#        发布新策略时 live/backup 代际在一个窗口内不一致 → -EAGAIN + 回退到
#        backup 重解析 → 重载窗口内出现干净内核没有的瞬态尾延迟/重试。
#
#     B  无效上下文的冗余解析（kernel/feature/selinux_hide.c
#        string_to_context_struct()）
#        live 策略的 MLS 解析失败后，仍对 backup(orig) 策略多跑一次
#        mls_context_to_sid() + MLS 后缀 memcpy，其结果在 out: 处被直接丢弃。
#        喂一个畸形 context，被 hook 的内核就比干净内核拒绝得更慢。
#
#     C  syscall dispatcher 固定开销（kernel/hook/syscall_hook_manager.c
#        ksu_sys_enter_handler() + kernel/feature/sucompat.c）
#        newfstatat/faccessat 是高频 syscall，原实现对「所有」进程都重定向进
#        KSU dispatcher，再在 sucompat 处理函数里按 allow-uid 提前返回。普通
#        App 因此在这两个 syscall 上每次都多一段固定的 dispatcher 往返开销，
#        最适合被动、纯无特权的检测。
#
# 本补丁的处理范围：
#   * 修 C：把 allow-uid 判定从 dispatcher 处理函数上提到 sys_enter tracepoint。
#           非授权进程的 newfstatat/faccessat 根本不进 dispatcher，直接走原生
#           快路径，消除该固定开销（检测 App 自身恰好是非授权进程）。
#   * 修 B：给 backup 解析加 `!rc` 守卫，live 解析一旦失败就不再多跑一次
#           backup 解析，使非法路径与原生内核一样只解析一次。
#   * 修 D：attr/current 写路径等时化 —— 换行前缀不再短路到 cred 分配出口，
#           user/role/type 三个字段的查找固定走完，backup 策略的字段查询推迟到
#           live 三字段全部通过之后。失败路径的耗时因此与首次失败的字段无关。
#   * 不动 A：策略重载竞态属于 policy_mutex 下的 RCU/代际时序重设计，盲改有
#           开机失败 / SELinux 判定错误的风险，必须在真机配合测量工具迭代验证，
#           故本脚本仅提示、不改动。详见 README.md。
#
# 行为保证：
#   - C：授权（root）App 行为不变；非授权 App 的 newfstatat/faccessat 结果不变，
#        只是少走一次 dispatcher 往返（sucompat 处理函数对它们本来就是直接放行）。
#   - B：合法 context（rc == 0）路径完全不变，隐藏正确性不受影响；仅非法路径提速。
#
# 所有改动均以内容检测守卫、可重复执行幂等；上游若自行修复 / 源码结构变化，
# 则按内容检测自动跳过（SKIP_INCOMPATIBLE=true 时降级为警告，不中断构建）。
#
# 用法: apply.sh [KernelSU 目录]（调用方工作目录需为 $KERNEL_ROOT）

set -eo pipefail

KSU_DIR="${1:-KernelSU}"

fail() {
  if [ "$SKIP_INCOMPATIBLE" = "true" ]; then
    echo "::warning title=隐藏层侧信道加固补丁已跳过::$1"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      echo "" >> "$GITHUB_STEP_SUMMARY"
      echo "> ⏭️ **隐藏层计时侧信道加固补丁** 已自动跳过：$1（构建未中断）" >> "$GITHUB_STEP_SUMMARY"
    fi
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -d "$KSU_DIR" ] || fail "未找到 KernelSU 目录: $KSU_DIR"

HOOK_FILE="$KSU_DIR/kernel/hook/syscall_hook_manager.c"
HIDE_FILE="$KSU_DIR/kernel/feature/selinux_hide.c"
SIDECHAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 信号 D 默认关闭：上游 PR #3981（2026-11-09 合并）已把 setprocattr 路径对齐 stock，
# 再叠加本补丁会反向偏离。仅在检测器只数方向、且真机确认需要时用 SIDECHAN_D=1 打开。
# 详见 README.md「启用开关与权衡」。
SIDECHAN_D="${SIDECHAN_D:-0}"

# ---------------------------------------------------------------------------
# 信号 C：tracepoint 层 allow-uid 门控（newfstatat / faccessat）
# ---------------------------------------------------------------------------
if [ -f "$HOOK_FILE" ] && grep -q 'ksu_sys_enter_handler' "$HOOK_FILE" \
  && grep -q 'if (ksu_has_syscall_hook(id)) {' "$HOOK_FILE"; then
  if grep -q 'KSU_SIDECHAN_C_GATE' "$HOOK_FILE"; then
    echo "syscall_hook_manager.c 已含信号 C 门控，跳过"
  else
    echo "应用信号 C 补丁：非授权进程的 newfstatat/faccessat 不进 dispatcher..."
    python3 - "$HOOK_FILE" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

# 1) 补头文件：current_uid() 来自 <linux/cred.h>，
#    ksu_is_allow_uid_for_current() 声明在 "policy/allowlist.h"。
inc_anchor = '#include "feature/sucompat.h"\n'
if inc_anchor not in text:
    sys.exit("找不到 include 锚点 feature/sucompat.h")
if '"policy/allowlist.h"' not in text:
    text = text.replace(
        inc_anchor,
        inc_anchor + '#include <linux/cred.h>\n#include "policy/allowlist.h"\n',
        1,
    )

# 2) 在 ksu_has_syscall_hook(id) 块内、current_regs 声明之后插入 allow-uid 门控。
#    放在声明之后，避免 declaration-after-statement（部分内核开 -Werror）。
hook_anchor = (
    "    if (ksu_has_syscall_hook(id)) {\n"
    "        struct pt_regs *current_regs = task_pt_regs(current);\n"
)
if hook_anchor not in text:
    sys.exit("找不到 ksu_has_syscall_hook(id) + current_regs 锚点")

gate = hook_anchor + (
    "\n"
    "        /*\n"
    "         * 侧信道加固（信号 C）：newfstatat/faccessat 是高频 syscall，原实现\n"
    "         * 对所有进程都重定向进 KSU dispatcher，再在 sucompat 处理函数里按\n"
    "         * allow-uid 提前返回；普通 App 因此在这两个 syscall 上每次都多一段\n"
    "         * 固定的 dispatcher 往返开销，可被无特权计时探测用来区分 KSU 内核与\n"
    "         * 干净内核。这里把 allow-uid 判定上提到 tracepoint：非授权进程直接走\n"
    "         * 原生快路径，不进 dispatcher，消除该固定开销。setresuid/execve/\n"
    "         * execveat 行为不变（execve/execveat 低频；setresuid 需对所有进程可见）。\n"
    "         */\n"
    "        if (id == __NR_newfstatat || id == __NR_faccessat) {\n"
    "            if (!ksu_is_allow_uid_for_current(current_uid().val))\n"
    "                return; /* KSU_SIDECHAN_C_GATE: native fast path for ordinary apps */\n"
    "        }\n"
)
text = text.replace(hook_anchor, gate, 1)

open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
print("  syscall_hook_manager.c: 已插入信号 C allow-uid 门控")
PYEOF
    grep -q 'KSU_SIDECHAN_C_GATE' "$HOOK_FILE" \
      || fail "信号 C 补丁应用后校验失败 (syscall_hook_manager.c)"
    grep -q '"policy/allowlist.h"' "$HOOK_FILE" \
      || fail "信号 C 补丁缺少 allowlist.h 头文件"
    echo "信号 C 已修复：非授权进程不再为 newfstatat/faccessat 支付 dispatcher 开销"
  fi
else
  echo "syscall_hook_manager.c 不存在或结构已变化，跳过信号 C 补丁"
fi

# ---------------------------------------------------------------------------
# 信号 B：string_to_context_struct() 失败路径不再冗余解析 backup 策略
# ---------------------------------------------------------------------------
if [ -f "$HIDE_FILE" ] && grep -q 'string_to_context_struct' "$HIDE_FILE"; then
  if grep -q 'KSU_SIDECHAN_B_GUARD' "$HIDE_FILE"; then
    echo "selinux_hide.c 已含信号 B 守卫，跳过"
  elif grep -q '^    if (orig_valid) {$' "$HIDE_FILE"; then
    # 'if (orig_valid) {' 在本文件中唯一（string_to_context_struct 内），可直接锚定。
    cnt=$(grep -c '^    if (orig_valid) {$' "$HIDE_FILE" || true)
    if [ "$cnt" != "1" ]; then
      fail "selinux_hide.c 的 'if (orig_valid)' 出现 $cnt 次（预期 1），上游结构可能已变化"
    fi
    echo "应用信号 B 补丁：live 解析失败时跳过 backup 冗余解析..."
    python3 - "$HIDE_FILE" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

old = "    if (orig_valid) {\n"
new = (
    "    /*\n"
    "     * 侧信道加固（信号 B）：当 live 策略的 MLS 解析已失败（rc != 0）时，下面\n"
    "     * 针对 backup(orig) 策略的第二次 mls_context_to_sid() + MLS 后缀 memcpy\n"
    "     * 的结果会在 out: 处被直接丢弃（orig_rc 被强制为 -EINVAL）。只在失败路径\n"
    "     * 上多做这一次解析，会让「喂畸形 context」的无特权探测测出 KSU 内核比干净\n"
    "     * 内核更慢。加 !rc 守卫：live 解析失败即跳过 backup 解析，使非法路径与原生\n"
    "     * 内核一样只解析一次；合法路径（rc == 0）行为完全不变。\n"
    "     */\n"
    "    if (orig_valid && !rc) { /* KSU_SIDECHAN_B_GUARD */\n"
)
if text.count(old) != 1:
    sys.exit("'if (orig_valid) {' 不唯一，拒绝修改")
text = text.replace(old, new, 1)

open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
print("  selinux_hide.c: backup 解析已加 !rc 守卫")
PYEOF
    grep -q 'KSU_SIDECHAN_B_GUARD' "$HIDE_FILE" \
      || fail "信号 B 补丁应用后校验失败 (selinux_hide.c)"
    echo "信号 B 已修复：畸形 context 的失败路径不再多跑一次 backup 解析"
  else
    fail "selinux_hide.c 未找到 'if (orig_valid) {' 锚点，上游结构可能已变化"
  fi
else
  echo "selinux_hide.c 不存在或无 string_to_context_struct，跳过信号 B 补丁"
fi

# ---------------------------------------------------------------------------
# 信号 D：attr/current 写路径等时化（换行前缀 vs 非法字段）
# ---------------------------------------------------------------------------
# 检测方式：成对写 /proc/self/attr/current，A=非法类型、B=换行前缀，两者都
# 必须返回 -EINVAL。若内核把换行首字节短路到 prepare_creds()/abort_creds() 的
# 失败出口，而非法字段在解析内部 early-return，两条失败路径就差一次 cred
# 分配/释放；再加上字段失败深度不同，方向计数会一边倒。
D_MARK='侧信道加固（信号 D）：原生内核在 str[0]'
if [ "$SIDECHAN_D" != "1" ]; then
  echo "信号 D 已按 SIDECHAN_D=$SIDECHAN_D 关闭（保持与 stock 一致；上游 #3981 已对齐该路径）"
elif [ -f "$HIDE_FILE" ] && grep -q 'my_setprocattr' "$HIDE_FILE" \
  && grep -q 'backup_string_to_context_struct' "$HIDE_FILE"; then
  if grep -qF "$D_MARK" "$HIDE_FILE"; then
    echo "selinux_hide.c 已含信号 D 等时化，跳过"
  elif [ ! -f "$SIDECHAN_DIR/patch_d.py" ]; then
    fail "缺少信号 D 补丁脚本: $SIDECHAN_DIR/patch_d.py"
  else
    echo "应用信号 D 补丁：attr/current 失败路径等时化..."
    python3 "$SIDECHAN_DIR/patch_d.py" "$HIDE_FILE" \
      || fail "信号 D 补丁应用失败（selinux_hide.c 锚点不匹配，上游结构可能已变化）"
    grep -qF "$D_MARK" "$HIDE_FILE" \
      || fail "信号 D 补丁应用后校验失败 (selinux_hide.c)"
    echo "信号 D 已修复：换行前缀与非法字段走同构失败路径，失败深度不再可测"
  fi
else
  echo "selinux_hide.c 不存在或无 attr/current 解析入口，跳过信号 D 补丁"
fi

# ---------------------------------------------------------------------------
# 信号 A：仅提示，不改动（见 README.md）
# ---------------------------------------------------------------------------
echo "::notice title=信号 A 未处理::策略发布竞态（rules.c/sepolicy.c 的 -EAGAIN 重载窗口）需真机配合测量工具迭代，本脚本不盲改，详见 scripts/sidechan_hide/README.md"

echo "隐藏层计时侧信道加固补丁处理完成（已处理 B/C/D，A 仅提示）"
