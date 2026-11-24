#!/usr/bin/env bash
# tiann/KernelSU #3877 同源「失败路径时序对齐」补丁（SukiSU-Nova builtin 分支）
#
# 上游参照：KernelSU-Next v3.4.2 的 #1601 == tiann/KernelSU #3877
#   fix(kernel): fix time side-channel detection in selinux hide
#   (5ec1cff, 2026-10-10 合并, 214+/125-, 只动 kernel/feature/selinux_hide.c)
#
# #3877 的实际内容是「把冗余工作量删掉，让 hooked 路径与 stock 同构」：
#   * 去掉 my_write_context()/my_write_access() 里那次额外的
#     security_context_to_sid()（注释 // sync to global sidtab），
#     改由 security_context_to_sid_with_policy(..., orig_sid_p, orig_rc_p) 在一次
#     kmemdup + 一个 rcu_read_lock() 段内同时喂 backup 与 live 两个策略；
#   * my_setprocattr() 回到 stock 的 prepare_creds()/commit_creds() 形状；
#   * 删掉 <6.6 的 fake_state，补 6.18 的 cred_security_struct 兼容。
#
# builtin 分支已经吃到这套骨架（signature 带 orig_sid_p/orig_rc_p、live sidtab 同步在
# 同一个 RCU 段内、单次 kmemdup），但 stock string_to_context_struct() 的两处
# 「未知字段立即返回」没跟上。返回值一样、耗时不一样，就是 #3877 要堵的口子：
#
#   信号 E  未知 user / role 不早退
#     stock:   usrdatum = symtab_search(&pol->p_users, scontextp);
#              if (!usrdatum) goto out;
#     builtin: 只把 live_valid 置 false，继续扫 role、type、MLS 后缀，
#              并对 orig 策略多做一次 symtab_search。
#     后果：「u:r:<超长 type>:s0」这类非法 context，干净内核在 user 字段就 -EINVAL,
#           隐藏内核要把整串扫完才 -EINVAL，差值随输入长度增长（百纳秒级）。
#
#   信号 F  单换行写 attr/current 走了另一条路径
#     stock / 上游 main: if (size && str[0] && str[0] != '\n')
#     builtin:           if (size && str[0])
#     后果：写 "\n" 时干净内核跳过解析、经 prepare_creds()/abort_creds() 才 -EINVAL；
#           隐藏内核在解析层早退（-EINVAL 且不分配 cred）。成对计时（非法类型 vs 换行）
#           长期偏一边——就是报告里 attr/current 那一对。
#
# 语义保证：两处都只改「走多深」，不改错误码、不改 sid 结果、不改隐藏判定。
#   信号 E：rc 本来就是 -EINVAL，out: 处同样把 orig_rc 强制成 -EINVAL 并销毁两个
#           context，与原路径完全等价，只是少扫了后面几段字面量。
#   信号 F：写 "\n" 仍然返回 -EINVAL（sid == 0 → abort_change），只是改走 stock 的
#           cred 路径，与干净内核同一形状。
#
# 幂等：已含标记或已具上游形状则跳过；SKIP_INCOMPATIBLE=true 时降级为警告。
# 用法: apply.sh [KernelSU 目录]（调用方工作目录需为 $KERNEL_ROOT）

set -eo pipefail

KSU_DIR="${1:-KernelSU}"
F="$KSU_DIR/kernel/feature/selinux_hide.c"

fail() {
  if [ "${SKIP_INCOMPATIBLE:-false}" = "true" ]; then
    echo "::warning title=#3877 同源时序补丁已跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -f "$F" ] || fail "未找到 $F"

if grep -q "KSU_SIDECHAN_3877_FASTFAIL" "$F" && grep -q "KSU_SIDECHAN_3877_NEWLINE" "$F"; then
  echo "selinux_hide.c 已含 #3877 同源补丁（E/F），跳过"
  exit 0
fi

python3 - "$F" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()
changed = []


def sub_once(old, new, tag, label):
    """replace exactly one occurrence; tolerate already-patched upstream shape"""
    global text
    if tag in text:
        print("  SKIP %s: 已含标记 %s" % (label, tag))
        return
    cnt = text.count(old)
    if cnt == 0:
        print("  SKIP %s: 未找到锚点（上游形状可能已变）" % label)
        return
    if cnt != 1:
        sys.exit("  %s: 锚点出现 %d 次（预期 1），拒绝修改" % (label, cnt))
    text = text.replace(old, new, 1)
    changed.append(label)
    print("  %s: 已应用 (%s)" % (label, tag))


# --- 信号 E1：未知 user 早退 ---
# 上游 main 的形状：
#     usrdatum = symtab_search(&pol->p_users, scontextp);
#     if (!usrdatum) goto out;
#     ctx->user = usrdatum->value;
#     orig_usrdatum = symtab_search(&orig_pol->p_users, scontextp);
E1_OLD = (
    "    usrdatum = symtab_search(&pol->p_users, scontextp);\n"
    "    orig_usrdatum = symtab_search(&orig_pol->p_users, scontextp);\n"
    "    if (usrdatum)\n"
    "        ctx->user = usrdatum->value;\n"
    "    else\n"
    "        live_valid = false;\n"
    "    if (orig_usrdatum)\n"
    "        orig_ctx->user = orig_usrdatum->value;\n"
    "    else\n"
    "        orig_valid = false;\n"
)
E1_NEW = (
    "    usrdatum = symtab_search(&pol->p_users, scontextp);\n"
    "    /*\n"
    "     * KSU_SIDECHAN_3877_FASTFAIL: stock string_to_context_struct() 在未知 user\n"
    "     * 处直接 -EINVAL 返回；继续往下扫 role/type/MLS 会让失败路径的耗时随\n"
    "     * context 长度增长（tiann/KernelSU #3877 消的就是这类长度相关的时序差）。\n"
    "     */\n"
    "    if (!usrdatum)\n"
    "        goto out;\n"
    "    ctx->user = usrdatum->value;\n"
    "\n"
    "    orig_usrdatum = symtab_search(&orig_pol->p_users, scontextp);\n"
    "    if (orig_usrdatum)\n"
    "        orig_ctx->user = orig_usrdatum->value;\n"
    "    else\n"
    "        orig_valid = false;\n"
)
sub_once(E1_OLD, E1_NEW, "KSU_SIDECHAN_3877_FASTFAIL", "信号 E1 未知 user 早退")

# --- 信号 E2：未知 role 早退 ---
E2_OLD = (
    "    role = symtab_search(&pol->p_roles, scontextp);\n"
    "    orig_role = symtab_search(&orig_pol->p_roles, scontextp);\n"
    "    if (role)\n"
    "        ctx->role = role->value;\n"
    "    else\n"
    "        live_valid = false;\n"
    "    if (orig_role)\n"
    "        orig_ctx->role = orig_role->value;\n"
    "    else\n"
    "        orig_valid = false;\n"
)
E2_NEW = (
    "    role = symtab_search(&pol->p_roles, scontextp);\n"
    "    /* 同上：未知 role 在 stock 上就此返回，不再扫 type/MLS */\n"
    "    if (!role)\n"
    "        goto out;\n"
    "    ctx->role = role->value;\n"
    "\n"
    "    orig_role = symtab_search(&orig_pol->p_roles, scontextp);\n"
    "    if (orig_role)\n"
    "        orig_ctx->role = orig_role->value;\n"
    "    else\n"
    "        orig_valid = false;\n"
)
sub_once(E2_OLD, E2_NEW, "KSU_SIDECHAN_3877_FASTFAIL", "信号 E2 未知 role 早退")

# --- 信号 F：单换行短路，回到 stock 形状 ---
F_OLD = (
    "    /* Keep every non-empty value on the backup validation path */\n"
    "    if (size && str[0]) {\n"
)
F_NEW = (
    "    /*\n"
    "     * KSU_SIDECHAN_3877_NEWLINE: 与 stock 的 !='\\n' 短路对齐。\n"
    "     * 写单个换行时 stock 跳过解析、走 prepare_creds()/abort_creds() 后 -EINVAL；\n"
    "     * 这里若跟进解析层，就是「更快的 -EINVAL」，成对计时立刻偏一边。\n"
    "     */\n"
    "    if (size && str[0] && str[0] != '\\n') {\n"
)
sub_once(F_OLD, F_NEW, "KSU_SIDECHAN_3877_NEWLINE", "信号 F 换行短路")

if not changed:
    print("  builtin 已是上游形状，无需改动")
    sys.exit(0)

open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(text)
print("  写入完成: %d 处" % len(changed))
PYEOF

# 校验：打了就该有标记；一处都没打说明上游已自带，视为通过
if grep -q "KSU_SIDECHAN_3877_FASTFAIL" "$F"; then
  grep -q "if (!usrdatum)" "$F" || fail "E1 落地校验失败（未找到 if (!usrdatum)）"
  grep -q "if (!role)" "$F" || fail "E2 落地校验失败（未找到 if (!role)）"
fi
if grep -q "KSU_SIDECHAN_3877_NEWLINE" "$F"; then
  grep -q "str\[0\] != '\\n'" "$F" || fail "F 落地校验失败（未找到 str[0] != 换行）"
fi

echo "#3877 同源时序对齐完成：未知 user/role 早退 + attr/current 换行短路与 stock 一致"
