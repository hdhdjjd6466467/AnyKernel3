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
#   * 不动 D：attr/current 的 setprocattr 时序。上游 PR #3981（2026-11-09 合并）已把
#           该路径对齐 stock（保留换行短路 + 单次解析），main 已包含；此处保持原样，
#           任何"把 A/B 拉平"的改动都会在绝对延迟上与 stock 分叉。
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
# 信号 D（attr/current 换行前缀 vs 非法字段）：不做。上游已处理，见 README.md
# ---------------------------------------------------------------------------
# tiann/KernelSU PR #3981（2026-11-09 合并）用同一个探针把 setprocattr 恢复到
# stock 形状：保留 str[0] != '\n' 短路，解析改成单次 security_context_to_sid_live()，
# 仅 type mark stale（-EAGAIN）时回退 dual parse。main 已包含该修复，本脚本保持
# 这条路径不动 —— 任何"把 A/B 拉平"的改动都会与 stock 分叉。
echo "信号 D 不处理：上游 PR #3981 已把 setprocattr 对齐 stock，本脚本保持原样"

# ---------------------------------------------------------------------------
# 信号 A：original-types 元数据与 live 策略的代际错位
#
# 根因（kernel/selinux/rules.c）：
#   apply_kernelsu_rules() / handle_sepolicy() 在 rcu_assign_pointer() 之前就调用
#   ksu_set_original_types() / ksu_advance_original_types()，把 ksu_original_types_*
#   切到「新 db + 新代际」。而在策略指针发布前，读者拿到的仍是旧 live 策略：
#     ksu_type_is_original(old_db, new_gen, v) → original_types_policy(new_db) != old_db
#     → 返回 -1 → backup_string_to_context_struct() 判定 -EAGAIN → 多走一次回退解析。
#   这个窗口不是几条指令，而是「构建整棵规则」的整个过程（毫秒级），期间任何
#   无特权进程的 context_to_sid（含 attr/current 写、access 查询）都多付一次解析，
#   正是报告里 A 信号的瞬态尾延迟来源。
#
# 修法（与上游 #3964 同思路：代际只随策略指针一起对外可见）：
#   把 original-types 元数据发布挪到 rcu_assign_pointer() 之后、synchronize_rcu()
#   之前。发布前读者用旧策略+旧元数据（一致），发布后新策略+新元数据（一致），
#   残留窗口只剩两条写指令之间；命中时仍走既有 -EAGAIN 重试，与 stock 的
#   sidtab_freeze/-ESTALE 重试同构。策略内容、SID 分配、隐藏语义均不变。
# ---------------------------------------------------------------------------
RULES_FILE="$KSU_DIR/kernel/selinux/rules.c"
if [ -f "$RULES_FILE" ] && grep -q 'apply_kernelsu_rules' "$RULES_FILE"; then
  if grep -q 'KSU_SIDECHAN_A_PUBLISH' "$RULES_FILE"; then
    echo "rules.c 已含信号 A 修复，跳过"
  else
    echo "应用信号 A 补丁：original-types 元数据改为随策略指针一起发布..."
    python3 - "$RULES_FILE" <<'PYEOF'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

ASSIGN = "    rcu_assign_pointer(selinux_state.policy, pol);\n"

COMMENT = (
    "    /*\n"
    "     * 侧信道加固（信号 A）：original-types 元数据必须与 live 策略在同一代际上\n"
    "     * 发布。原顺序在 rcu_assign_pointer() 之前就切到新代际，构建规则的整个窗口\n"
    "     * 内读者看到的是「旧 live 策略 + 新代际元数据」，ksu_type_is_original()\n"
    "     * 返回 -1，backup_string_to_context_struct() 因此返回 -EAGAIN，多走一次\n"
    "     * 回退解析，形成干净内核没有的瞬态尾延迟。移到 rcu_assign_pointer() 之后，\n"
    "     * 元数据与 live 策略始终同代际，窗口收敛到两条写指令之间；命中时仍按既有\n"
    "     * -EAGAIN 路径重试，与 stock 的 sidtab_freeze/-ESTALE 重试同构。\n"
    "     */\n"
    "    /* KSU_SIDECHAN_A_PUBLISH */\n"
)

PAT_INITIAL = re.compile(
    r"[ \t]*if \(!ksu_set_original_types\([^\n]*\)\)\n"
    r"[ \t]*pr_warn\([^\n]*\);\n"
)
PAT_UPDATE = re.compile(
    r"[ \t]*if \(!ksu_advance_original_types\([^\n]*\)\)\n"
    r"[ \t]*pr_warn\([^\n]*\);\n"
)


def region_of(src, start_marker):
    i = src.find(start_marker)
    if i < 0:
        return None
    j = src.find("\n}\n", i)
    if j < 0:
        return None
    return i, j + 3


def patch(src, func_start, pattern):
    r = region_of(src, func_start)
    if not r:
        return None, "找不到函数 %s" % func_start
    i, j = r
    region = src[i:j]
    m = pattern.search(region)
    if not m:
        return None, "%s 中找不到 original-types 发布调用" % func_start
    call = m.group(0)
    region = region.replace(call, "", 1)
    if ASSIGN not in region:
        return None, "%s 中找不到 rcu_assign_pointer 锚点" % func_start
    region = region.replace(ASSIGN, ASSIGN + COMMENT + call, 1)
    return src[:i] + region + src[j:], None


text, err = patch(text, "apply_kernelsu_rules(", PAT_INITIAL)
if err:
    print("  SKIP: " + err)
    sys.exit(0)
text, err = patch(text, "handle_sepolicy(", PAT_UPDATE)
if err:
    print("  SKIP: " + err)
    sys.exit(0)

# newline="" 避免 Windows 上把 LF 改写成 CRLF（CI 在 Linux 上无差异）
open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(text)
print("  rules.c: original-types 元数据已改为随策略指针发布")
PYEOF
    if grep -q 'KSU_SIDECHAN_A_PUBLISH' "$RULES_FILE"; then
      echo "信号 A 已修复：策略发布窗口内不再出现旧策略/新代际的 -EAGAIN 回退解析"
    else
      echo "::warning title=信号 A 顺序补丁跳过::rules.c 结构与上游不同（$KSU_DIR），已跳过，不影响构建"
    fi
  fi
else
  echo "rules.c 不存在或无 apply_kernelsu_rules，跳过信号 A 补丁"
fi

# ---------------------------------------------------------------------------
# 信号 A（续）：original-types 三元组的撕裂读
#
# sepolicy.c 里 limit / generation 是两个独立 WRITE_ONCE，policy 指针是第三个。
# 读者按 (policy, limit, generation) 三次 READ_ONCE 取值，可能拼出
# 「新 limit + 旧 generation + 旧 policy」：只要 generation 恰好等于读者传入的
# 代数，ksu_type_is_original() 就会用错误的 limit 把 KSU 新增类型判成 original，
# 这是真正的隐藏绕过窗口，不只是性能问题（当前上游代码就有）。
#
# 修法：limit 与 generation 压进同一个 u64（low32=limit, high32=generation），
# 单次 WRITE_ONCE 发布；policy 指针先写。arm64 上对齐 64 位写是单次原子，
# 读者拿到的 (limit, generation) 永远同代，任何与 policy 指针的错配都只会让
# 代际比较失败返回 -1（走既有重试），不会产生错误的 1/0。
# 对外签名 ksu_type_is_original()/ksu_set_original_types()/ksu_advance_original_types()
# 全部不变，selinux_hide.c 不需要改。
# ---------------------------------------------------------------------------
SEPOLICY_FILE="$KSU_DIR/kernel/selinux/sepolicy.c"
if [ -f "$SEPOLICY_FILE" ] && grep -q 'ksu_original_types_' "$SEPOLICY_FILE"; then
  if grep -q 'ksu_original_types_view' "$SEPOLICY_FILE"; then
    echo "sepolicy.c 已含信号 A 原子发布，跳过"
  elif ! grep -q 'ksu_original_types_limit' "$SEPOLICY_FILE"; then
    echo "sepolicy.c 结构已变化（无三写路径），跳过信号 A 原子发布补丁"
  else
    echo "应用信号 A 补丁（续）：original-types 的 limit/generation 合并为单次原子发布..."
    python3 - "$SEPOLICY_FILE" <<'PYEOF'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

OLD_DECL = (
    "static const struct policydb *ksu_original_types_policy;\n"
    "static u32 ksu_original_types_limit;\n"
    "static u32 ksu_original_types_generation;\n"
)

NEW_DECL = (
    "/*\n"
    " * 侧信道加固（信号 A）：limit 与 generation 必须同生同灭。\n"
    " * 旧实现是两个独立 WRITE_ONCE，读者可能拼出「新 limit + 旧 generation」，\n"
    " * 一旦 generation 与调用方传入的代数相同，就会用错误的 limit 把 KSU 新增\n"
    " * 类型判成 original —— 真实的隐藏绕过窗口。压进一个 u64 后单次原子发布，\n"
    " * 读者看到的 (limit, generation) 永远同代；与 policy 指针错配只会得到 -1。\n"
    " */\n"
    "/* KSU_SIDECHAN_A_ATOMIC */\n"
    "static const struct policydb *ksu_original_types_policy;\n"
    "static u64 ksu_original_types_view; /* low32: limit, high32: generation */\n"
    "\n"
    "static void ksu_original_types_publish(const struct policydb *db, u32 limit, u32 generation)\n"
    "{\n"
    "    WRITE_ONCE(ksu_original_types_policy, db);\n"
    "    WRITE_ONCE(ksu_original_types_view, ((u64)generation << 32) | (u64)limit);\n"
    "}\n"
)

if OLD_DECL not in text:
    print("  SKIP: 找不到 original-types 三个全局声明")
    sys.exit(0)
text = text.replace(OLD_DECL, NEW_DECL, 1)

start = text.find("bool ksu_set_original_types(")
end_marker = "return type_value && type_value <= original_types_limit ? 1 : 0;\n}\n"
end = text.find(end_marker, start)
if start < 0 or end < 0:
    print("  SKIP: 找不到 ksu_set_original_types / ksu_type_is_original 区域")
    sys.exit(0)
end += len(end_marker)

NEW_BODY = (
    "bool ksu_set_original_types(struct policydb *db, struct policydb *orig_db, u32 policy_generation)\n"
    "{\n"
    "    if (!db || !orig_db || !policy_generation || orig_db->p_types.nprim > db->p_types.nprim) {\n"
    "        ksu_original_types_publish(NULL, 0, 0);\n"
    "        return false;\n"
    "    }\n"
    "\n"
    "    ksu_original_types_publish(db, orig_db->p_types.nprim, policy_generation);\n"
    "    return true;\n"
    "}\n"
    "\n"
    "bool ksu_advance_original_types(struct policydb *db, struct policydb *old_db, u32 old_policy_generation,\n"
    "                                u32 policy_generation)\n"
    "{\n"
    "    u64 view = READ_ONCE(ksu_original_types_view);\n"
    "    u32 original_types_limit = (u32)view;\n"
    "    u32 original_types_generation = (u32)(view >> 32);\n"
    "\n"
    "    if (!db || !old_db || !old_policy_generation || !policy_generation || !original_types_limit ||\n"
    "        !original_types_generation || old_policy_generation != original_types_generation ||\n"
    "        READ_ONCE(ksu_original_types_policy) != old_db || db->p_types.nprim < original_types_limit) {\n"
    "        ksu_original_types_publish(NULL, 0, 0);\n"
    "        return false;\n"
    "    }\n"
    "\n"
    "    ksu_original_types_publish(db, original_types_limit, policy_generation);\n"
    "    return true;\n"
    "}\n"
    "\n"
    "int ksu_type_is_original(struct policydb *db, u32 policy_generation, u32 type_value)\n"
    "{\n"
    "    u64 view = READ_ONCE(ksu_original_types_view);\n"
    "    const struct policydb *original_types_policy = READ_ONCE(ksu_original_types_policy);\n"
    "    u32 original_types_limit = (u32)view;\n"
    "    u32 original_types_generation = (u32)(view >> 32);\n"
    "\n"
    "    if (!db || !policy_generation || original_types_policy != db ||\n"
    "        original_types_generation != policy_generation || !original_types_limit ||\n"
    "        type_value > db->p_types.nprim)\n"
    "        return -1;\n"
    "\n"
    "    return type_value && type_value <= original_types_limit ? 1 : 0;\n"
    "}\n"
)

text = text[:start] + NEW_BODY + text[end:]
open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(text)
print("  sepolicy.c: limit/generation 已合并为单次原子发布")
PYEOF
    grep -q 'KSU_SIDECHAN_A_ATOMIC' "$SEPOLICY_FILE" \
      || fail "信号 A 原子发布补丁应用后校验失败 (sepolicy.c)"
    if grep -q 'ksu_original_types_limit\|ksu_original_types_generation' "$SEPOLICY_FILE" && grep -q 'KSU_SIDECHAN_A_ATOMIC' "$SEPOLICY_FILE"; then
      echo "::warning title=信号 A 原子发布残留::sepolicy.c 仍有旧的三写路径"
    fi
    echo "信号 A 处理完成（若已跳过会单独告警）"
  fi
else
  echo "sepolicy.c 不存在或结构已变化，跳过信号 A 原子发布补丁"
fi

echo "隐藏层计时侧信道加固补丁处理完成（已处理 A/B/C；D 交由上游 #3981）"