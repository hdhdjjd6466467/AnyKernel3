#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""attr/current 读取侧伪装。

SELinux 隐藏只做了写入方向（my_setprocattr / SUSFS 的 setprocattr hook），
读取方向的 selinux_getprocattr 仍把真实标签交出去 —— 普通 App 读
/proc/<pid>/attr/current 就能看到 u:r:su:s0、u:r:ksu:s0。检测器遍历一遍
/proc 即可列出所有 su/ksu 进程。

两条实现路径，按 KSU 分支自动选择：

  1. main 分支（有 ksu_lsm_hook 框架）：在 kernel/feature/selinux_hide.c
     里挂 selinux_getprocattr，用 .original 调原函数后替换可疑标签。
  2. builtin 分支（SUSFS 内建，无 lsm_hook 框架）：直接给内核
     security/selinux/hooks.c 的 selinux_getprocattr 注入伪装逻辑。

两条路径都不动 sucompat，su 命令照常可用。

退出码：0 = 成功或已应用；2 = 结构不匹配（由调用方按 SKIP_INCOMPATIBLE 处理）；
        1 = 其他错误。
"""

import os
import sys

MARK = "KSU_ATTR_SPOOF"
FAKE = "u:r:untrusted_app:s0"

LSM_IMPL = r'''
/*
 * KSU_ATTR_SPOOF: attr/current 读取侧伪装。
 *
 * 非授权 uid 读取 attr/current 时，凡带 :su: / :ksu / magisk / apatch 的标签
 * 一律换成 u:r:untrusted_app:s0。授权进程（管理器、su 会话自身）仍看到真实标签。
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

KERNEL_IMPL = (
    "\t/*\n"
    "\t * KSU_ATTR_SPOOF: 非授权读取者的 attr/current 伪装。\n"
    "\t * 检测器遍历 /proc/<pid>/attr/current 时，su/ksu/magisk 域会直接暴露\n"
    "\t * 隐藏状态；这里把可疑标签换成 untrusted_app。授权 uid 不受影响。\n"
    "\t */\n"
    "\tif (!strcmp(name, \"current\") && current_uid().val >= 10000 &&\n"
    "\t    (strstr(*value, \":su:\") || strstr(*value, \":ksu\") ||\n"
    "\t     strstr(*value, \"magisk\") || strstr(*value, \"apatch\"))) {\n"
    "\t\tchar *ksu_fake = kstrdup(\"u:r:untrusted_app:s0\", GFP_KERNEL);\n"
    "\n"
    "\t\tif (ksu_fake) {\n"
    "\t\t\tkfree(*value);\n"
    "\t\t\t*value = ksu_fake;\n"
    "\t\t\tlen = (unsigned)strlen(ksu_fake) + 1;\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
)


def rep(text, old, new, tag):
    n = text.count(old)
    if n != 1:
        raise ValueError("[%s] anchor %d (expect 1)" % (tag, n))
    print("  ok: %s" % tag)
    return text.replace(old, new, 1)


def patch_ksu(path):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    if MARK in text:
        print("selinux_hide.c 已含伪装，跳过")
        return 0

    text = rep(
        text,
        '#include "selinux_hide.h"\n',
        '#include "selinux_hide.h"\n#include "policy/allowlist.h"\n',
        "include allowlist",
    )

    anchor_call = "    return ((setprocattr_fn)selinux_setprocattr_hook.original)(name, value, size);\n}\n"
    text = rep(text, anchor_call, anchor_call + LSM_IMPL, "getprocattr impl")

    anchor_reg = (
        "    ret = ksu_lsm_hook(&selinux_setprocattr_hook);\n"
        "    if (ret) {\n"
        '        pr_err("selinux_hide: init: selinux_setprocattr_hook err: %d\\n", ret);\n'
        "        goto unhook;\n"
        "    }\n"
    )
    reg = anchor_reg + (
        "\n"
        "    ret = ksu_lsm_hook(&selinux_getprocattr_hook);\n"
        "    if (ret) {\n"
        '        pr_err("selinux_hide: init: selinux_getprocattr_hook err: %d\\n", ret);\n'
        "        goto unhook;\n"
        "    }\n"
    )
    text = rep(text, anchor_reg, reg, "register hook")

    anchor_unreg = "    ksu_lsm_unhook(&selinux_setprocattr_hook);\n"
    text = rep(text, anchor_unreg, anchor_unreg + "    ksu_lsm_unhook(&selinux_getprocattr_hook);\n", "unregister hook")

    open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
    print("attr/current 伪装已注入 selinux_hide.c")
    return 0


def patch_kernel(path):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    if MARK in text:
        print("hooks.c 已含伪装，跳过")
        return 0

    sig = "static int selinux_getprocattr(struct task_struct *p,"
    i = text.find(sig)
    if i < 0:
        print("hooks.c 未找到 selinux_getprocattr", file=sys.stderr)
        return 2

    brace = text.find("{", i)
    depth = 0
    j = brace
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1

    body = text[brace:j]
    anchor = "\treturn len;\n"
    pos = body.rfind(anchor)
    if pos < 0:
        print("selinux_getprocattr 内未找到 return len;", file=sys.stderr)
        return 2

    ins = brace + pos
    text = text[:ins] + KERNEL_IMPL + text[ins:]
    open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
    print("attr/current 伪装已注入 security/selinux/hooks.c")
    return 0


def main():
    ksu_dir = sys.argv[1] if len(sys.argv) > 1 else "KernelSU"
    hide = os.path.join(ksu_dir, "kernel", "feature", "selinux_hide.c")
    hooks = os.path.join("security", "selinux", "hooks.c")

    if os.path.isfile(hide):
        text = open(hide, encoding="utf-8", errors="surrogateescape").read()
        if "KSU_LSM_HOOK_INIT" in text:
            print("走 KSU lsm_hook 路径")
            try:
                return patch_ksu(hide)
            except ValueError as e:
                print("锚点不匹配: %s" % e, file=sys.stderr)
                return 2
        print("selinux_hide.c 无 KSU_LSM_HOOK_INIT（builtin 分支）")

    if os.path.isfile(hooks):
        print("走内核 selinux_getprocattr 路径")
        return patch_kernel(hooks)

    print("既无 KSU lsm_hook 框架也无 security/selinux/hooks.c，跳过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
