#!/usr/bin/env bash
# attr/current 读取侧伪装（KSU_ATTR_SPOOF）
#
# 背景：SELinux 隐藏目前只做了写入方向 —— my_setprocattr()（以及 SUSFS 的
# setprocattr hook）负责让非授权的写返回 EINVAL；但读取方向没有对偶处理，
# 普通 App 读一次 /proc/<pid>/attr/current 就能看到 u:r:su:s0、u:r:ksu:s0
# 这类域。Duck Detector 的 SU 卡片正是遍历一遍 /proc 的 attr/current，
# 把带 :su: / ksu / magisk 的进程全部列出来。
#
# 本补丁在 ksu_lsm_hook 上挂 selinux_getprocattr，对非授权 uid 的读取，
# 把可疑标签换成 u:r:untrusted_app:s0；授权进程（管理器、su 会话自身）
# 仍看到真实标签。不改 sucompat，su 命令照常可用。
#
# 用法: attr_spoof/apply.sh [KernelSU 目录]（调用方工作目录需为 KERNEL_ROOT）

set -eo pipefail

KSU_DIR="${1:-KernelSU}"

fail() {
  if [ "$SKIP_INCOMPATIBLE" = "true" ]; then
    echo "::warning title=attr/current 伪装补丁已跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

HIDE_FILE="$KSU_DIR/kernel/feature/selinux_hide.c"

[ -d "$KSU_DIR" ] || fail "未找到 KernelSU 目录: $KSU_DIR"

if [ ! -f "$HIDE_FILE" ]; then
  echo "selinux_hide.c 不存在，跳过 attr/current 伪装补丁"
  exit 0
fi

if grep -q 'KSU_ATTR_SPOOF' "$HIDE_FILE"; then
  echo "selinux_hide.c 已含 attr/current 伪装，跳过"
  exit 0
fi

echo "应用 attr/current 读取侧伪装..."
if ! python3 - "$HIDE_FILE" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

def rep(old, new, tag):
    global text
    n = text.count(old)
    if n != 1:
        raise SystemExit("[%s] anchor %d (expect 1)" % (tag, n))
    text = text.replace(old, new, 1)
    print("  ok:", tag)

rep(
    '#include "selinux_hide.h"\n',
    '#include "selinux_hide.h"\n#include "policy/allowlist.h"\n',
    "include allowlist",
)

IMPL = r'''
/*
 * KSU_ATTR_SPOOF: attr/current 读取侧伪装。
 *
 * 非授权 uid 读取 attr/current 时，凡带 :su: / :ksu / magisk / apatch 的标签
 * 一律换成 u:r:untrusted_app:s0。授权进程仍看到真实标签。
 */
typedef int (*getprocattr_fn)(struct task_struct *p, char *name, char **value);
static int my_getprocattr(struct task_struct *p, char *name, char **value);
static struct ksu_lsm_hook selinux_getprocattr_hook =
    KSU_LSM_HOOK_INIT(getprocattr, "selinux_getprocattr", my_getprocattr, 0);

static bool ksu_context_needs_spoof(const char *context)
{
    if (!context)
        return false;

    return strstr(context, ":su:") || strstr(context, ":ksu") || strstr(context, "magisk") ||
           strstr(context, "apatch");
}

static int __nocfi my_getprocattr(struct task_struct *p, char *name, char **value)
{
    int ret;
    char *fake;

    ret = ((getprocattr_fn)selinux_getprocattr_hook.original)(p, name, value);
    if (ret <= 0 || !value || !*value)
        return ret;

    if (strcmp(name, "current"))
        return ret;

    /* 授权进程（管理器 / su 会话自身）看到真实标签 */
    if (ksu_is_allow_uid_for_current(current_uid().val))
        return ret;

    if (!ksu_context_needs_spoof(*value))
        return ret;

    fake = kstrdup("u:r:untrusted_app:s0", GFP_KERNEL);
    if (!fake)
        return ret;

    kfree(*value);
    *value = fake;

    return (int)strlen(fake) + 1;
}
'''

ANCHOR_CALL = "    return ((setprocattr_fn)selinux_setprocattr_hook.original)(name, value, size);\n}\n"
rep(ANCHOR_CALL, ANCHOR_CALL + IMPL, "getprocattr impl")

ANCHOR_REG = ("    ret = ksu_lsm_hook(&selinux_setprocattr_hook);\n"
              "    if (ret) {\n"
              "        pr_err(\"selinux_hide: init: selinux_setprocattr_hook err: %d\\n\", ret);\n"
              "        goto unhook;\n"
              "    }\n")
REG = ANCHOR_REG + ("\n"
    "    ret = ksu_lsm_hook(&selinux_getprocattr_hook);\n"
    "    if (ret) {\n"
    "        pr_err(\"selinux_hide: init: selinux_getprocattr_hook err: %d\\n\", ret);\n"
    "        goto unhook;\n"
    "    }\n")
rep(ANCHOR_REG, REG, "register hook")

ANCHOR_UNREG = "    ksu_lsm_unhook(&selinux_setprocattr_hook);\n"
rep(ANCHOR_UNREG, ANCHOR_UNREG + "    ksu_lsm_unhook(&selinux_getprocattr_hook);\n", "unregister hook")

open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
print("attr/current 伪装已注入")
PYEOF
then
  echo "--- 诊断 ---"
  echo "ksu_lsm_hook 出现次数: $(grep -c 'ksu_lsm_hook' "$HIDE_FILE" || true)"
  grep -n 'my_setprocattr' "$HIDE_FILE" | head -3 || true
  grep -n 'KSU_LSM_HOOK_INIT' "$HIDE_FILE" | head -3 || true
  fail "attr/current 伪装补丁应用失败：当前 KSU 分支没有 ksu_lsm_hook 框架（SukiSU-Nova builtin 分支的 SELinux 钩子由内核侧 SUSFS 补丁内联调用，不走 LSM hook）"
fi

grep -q 'KSU_ATTR_SPOOF' "$HIDE_FILE" || fail "attr/current 伪装注入后校验失败"
grep -q 'selinux_getprocattr_hook' "$HIDE_FILE" || fail "attr/current 伪装缺少 hook 注册"
echo "attr/current 伪装完成：非授权读取不再看到 su/ksu/magisk 域"