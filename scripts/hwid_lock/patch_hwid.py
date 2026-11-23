#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主板 ID（HWID）绑定。

把一份 HWID 白名单编进内核，并在 KernelSU 的 setresuid 授权入口做校验：
非白名单设备不授予任何 KSU 能力。

HWID 来源（启动早期一次性解析）：saved_command_line、bootconfig、
DT /serial-number、DT /chosen/bootargs。匹配用边界检查。

注意：bootconfig 的 xbc_find_value 带 __init，只能在 early_initcall 里调用，
运行期调用会踩已释放段（modpost 会报 section mismatch 并让构建失败）。
因此把解析结果存进 ksu_hwid_ok，运行期只读标志。
"""

import os
import sys

MARK = "KSU_HWID_LOCK"

HEAD = """/*
 * KSU_HWID_LOCK: 主板 ID 绑定（构建时生成，勿手改）。
 *
 * 白名单为空时不做任何限制。
 */
#ifndef __KSU_HWID_LOCK_H
#define __KSU_HWID_LOCK_H

#include <linux/bootconfig.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/string.h>
#include <linux/types.h>

extern char *saved_command_line;

static const char *const ksu_hwid_whitelist[] = {
"""

TAIL = """};

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

static bool __init ksu_hwid_bootconfig(const char *id)
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

static bool ksu_hwid_ok __read_mostly = true;

static void __init ksu_hwid_resolve(void)
{
    struct device_node *np;
    const char *prop;
    int i;

    if (KSU_HWID_COUNT == 0) {
        ksu_hwid_ok = true;
        return;
    }

    ksu_hwid_ok = false;

    for (i = 0; i < KSU_HWID_COUNT; i++) {
        const char *id = ksu_hwid_whitelist[i];

        if (saved_command_line && ksu_hwid_hit(saved_command_line, id)) {
            ksu_hwid_ok = true;
            return;
        }
        if (ksu_hwid_bootconfig(id)) {
            ksu_hwid_ok = true;
            return;
        }
    }

    np = of_find_node_by_path("/");
    if (np) {
        prop = of_get_property(np, "serial-number", NULL);
        for (i = 0; i < KSU_HWID_COUNT; i++) {
            if (ksu_hwid_hit(prop, ksu_hwid_whitelist[i])) {
                ksu_hwid_ok = true;
                return;
            }
        }
    }

    np = of_find_node_by_path("/chosen");
    if (np) {
        prop = of_get_property(np, "bootargs", NULL);
        for (i = 0; i < KSU_HWID_COUNT; i++) {
            if (ksu_hwid_hit(prop, ksu_hwid_whitelist[i])) {
                ksu_hwid_ok = true;
                return;
            }
        }
    }
}

static int __init ksu_hwid_lock_init(void)
{
    ksu_hwid_resolve();
    if (!ksu_hwid_ok)
        pr_err("ksu: device not in HWID whitelist, KernelSU disabled");
    return 0;
}
early_initcall(ksu_hwid_lock_init);

static inline bool ksu_hwid_allowed(void)
{
    return ksu_hwid_ok;
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
    variants = []
    for s in items:
        s = s.replace(chr(34), "")
        for v in (s, s.upper(), s.lower()):
            if v not in variants:
                variants.append(v)
    body = "".join("    " + chr(34) + v + chr(34) + "," + chr(10) for v in variants)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEAD + body + TAIL)
    print("hwid whitelist %d ids (%d variants) -> %s" % (len(items), len(variants), path))


def inject(path):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    if MARK + "_GATE" in text:
        print("%s already gated" % path)
        return 0

    text = chr(35) + "include " + chr(34) + "hwid_lock.h" + chr(34) + " /* " + MARK + "_GATE */" + chr(10) + text

    sig = "int ksu_handle_setresuid("
    i = text.find(sig)
    if i < 0:
        print("%s: ksu_handle_setresuid not found" % path, file=sys.stderr)
        return 2

    brace = text.find("{", i)
    ins = brace + 1
    text = text[:ins] + chr(10) + GATE + text[ins:].lstrip(chr(10))

    open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
    print("%s gated" % path)
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
        print("no ksu_handle_setresuid hook file", file=sys.stderr)
        return 2

    items = read_list(os.environ.get("HWID_WHITELIST", ""))
    header = os.path.join(os.path.dirname(target), "hwid_lock.h")
    generate_header(items, header)

    if not items:
        print("whitelist empty, no gate injected")
        return 0

    return inject(target)


if __name__ == "__main__":
    sys.exit(main())