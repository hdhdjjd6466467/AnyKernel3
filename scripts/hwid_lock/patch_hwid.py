#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主板 ID（HWID）绑定。

把一份 HWID 白名单编进内核，并在 KernelSU 的 setresuid 授权入口做校验：
非白名单设备不授予任何 KSU 能力（su 不可用、管理器拿不到 fd）。

HWID 来源按优先级：
  1. saved_command_line（/proc/cmdline）里的 androidboot.cpuid / chipid / emmcid / serialno
  2. bootconfig（CONFIG_BOOT_CONFIG）里的同名 key
  3. device tree 的 /serial-number
  4. device tree 的 /chosen/bootargs

匹配用边界检查（前后必须是非字母数字），避免 8 位短 ID 撞上无关的十六进制串。
白名单为空时不做限制。

退出码：0 成功或跳过；2 结构不匹配。
"""

import os
import sys

MARK = "KSU_HWID_LOCK"

HEADER_HEAD = """/*
 * KSU_HWID_LOCK: 主板 ID 绑定（构建时生成，勿手改）。
 *
 * 白名单为空时不做任何限制；非空时，只允许列表内的 HWID 使用 KernelSU。
 */
#ifndef __KSU_HWID_LOCK_H
#define __KSU_HWID_LOCK_H

#include <linux/bootconfig.h>
#include <linux/ctype.h>
#include <linux/of.h>
#include <linux/string.h>
#include <linux/types.h>

extern char *saved_command_line;

static const char *const ksu_hwid_whitelist[] = {
"""

HEADER_TAIL = """};

#define KSU_HWID_COUNT ((int)(sizeof(ksu_hwid_whitelist) / sizeof(ksu_hwid_whitelist[0])))

/* 边界匹配：前后必须是非字母数字，避免短 ID 子串误命中 */
static inline bool ksu_hwid_hit(const char *hay, const char *id)
{
    size_t len;
    const char *p;

    if (!hay || !id || !id[0])
        return false;

    len = strlen(id);
    p = hay;

    while ((p = strstr(p, id)) != NULL) {
        char before = (p == hay) ? ' ' : p[-1];
        char after = p[len];

        if (!isalnum((unsigned char)before) && !isalnum((unsigned char)after))
            return true;

        p += len;
    }

    return false;
}

static inline bool ksu_hwid_bootconfig(const char *id)
{
    static const char *const keys[] = {
        "androidboot.cpuid",
        "androidboot.serialno",
        "androidboot.chipid",
        "androidboot.emmcid",
        "oplusboot.serialno",
    };
    struct xbc_node *node;
    const char *val;
    int i;

    for (i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); i++) {
        val = xbc_find_value(keys[i], &node);
        if (val && ksu_hwid_hit(val, id))
            return true;
    }

    return false;
}

static inline bool ksu_hwid_allowed(void)
{
    struct device_node *np;
    const char *prop;
    int i;

    /* 白名单为空：不限制 */
    if (KSU_HWID_COUNT == 0)
        return true;

    for (i = 0; i < KSU_HWID_COUNT; i++) {
        const char *id = ksu_hwid_whitelist[i];

        if (saved_command_line && ksu_hwid_hit(saved_command_line, id))
            return true;
        if (ksu_hwid_bootconfig(id))
            return true;
    }

    np = of_find_node_by_path("/");
    if (np) {
        prop = of_get_property(np, "serial-number", NULL);
        for (i = 0; i < KSU_HWID_COUNT; i++) {
            if (ksu_hwid_hit(prop, ksu_hwid_whitelist[i]))
                return true;
        }
    }

    np = of_find_node_by_path("/chosen");
    if (np) {
        prop = of_get_property(np, "bootargs", NULL);
        for (i = 0; i < KSU_HWID_COUNT; i++) {
            if (ksu_hwid_hit(prop, ksu_hwid_whitelist[i]))
                return true;
        }
    }

    return false;
}

#endif /* __KSU_HWID_LOCK_H */
"""

GATE = (
    "    /* KSU_HWID_LOCK: 非白名单设备不授予任何 KSU 能力 */\n"
    "    if (!ksu_hwid_allowed()) {\n"
    "        static bool warned;\n"
    "\n"
    "        if (!warned) {\n"
    "            warned = true;\n"
    "            pr_err(\"ksu: device not in HWID whitelist, KernelSU disabled\");\n"
    "        }\n"
    "        return 0;\n"
    "    }\n"
    "\n"
)


def read_list(env_value):
    items = []
    for raw in (env_value or "").replace(",", "\n").split("\n"):
        s = raw.strip()
        if s and not s.startswith("#"):
            items.append(s)
    return items


def generate_header(items, path):
    body = "".join('    "%s",\n' % s.replace('"', "") for s in items)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER_HEAD + body + HEADER_TAIL)
    print("hwid 白名单 %d 条 -> %s" % (len(items), path))


def inject(path):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    if MARK + "_GATE" in text:
        print("%s 已含 HWID 门控，跳过" % path)
        return 0

    text = '#include "hwid_lock.h" /* %s_GATE */\n' % MARK + text

    sig = "int ksu_handle_setresuid("
    i = text.find(sig)
    if i < 0:
        print("%s 未找到 ksu_handle_setresuid" % path, file=sys.stderr)
        return 2

    brace = text.find("{", i)
    ins = brace + 1
    text = text[:ins] + "\n" + GATE + text[ins:].lstrip("\n")

    open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
    print("%s 已注入 HWID 门控" % path)
    return 0


def main():
    ksu_dir = sys.argv[1] if len(sys.argv) > 1 else "KernelSU"
    hooks = [
        os.path.join(ksu_dir, "kernel", "hook", "setuid_hook.c"),
        os.path.join(ksu_dir, "kernel", "hook", "lsm_hook.c"),
    ]

    target = None
    for h in hooks:
        if os.path.isfile(h):
            text = open(h, encoding="utf-8", errors="surrogateescape").read()
            if "int ksu_handle_setresuid(" in text:
                target = h
                break

    if not target:
        print("未找到含 ksu_handle_setresuid 的 hook 文件", file=sys.stderr)
        return 2

    items = read_list(os.environ.get("HWID_WHITELIST", ""))
    header = os.path.join(os.path.dirname(target), "hwid_lock.h")
    generate_header(items, header)

    if not items:
        print("白名单为空，不注入门控（不限制）")
        return 0

    return inject(target)


if __name__ == "__main__":
    sys.exit(main())