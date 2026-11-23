#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主板 ID（HWID）绑定。

把一份 HWID 白名单编进内核，并在 KernelSU 的 setresuid 授权入口做校验：
非白名单设备不授予任何 KSU 能力（su 不可用、管理器拿不到 fd），白名单设备照常。

HWID 来源与设备 ID 查询脚本一致，按优先级从内核可见的几处取：

  1. saved_command_line 里的 androidboot.cpuid / chipid / emmcid / serialno
  2. device tree 的 /serial-number
  3. device tree 的 /chosen/bootargs

任一处出现白名单里的串即通过。白名单为空时不限制（保持原行为）。

退出码：0 成功或跳过；2 结构不匹配。
"""

import os
import sys

MARK = "KSU_HWID_LOCK"

HEADER_TMPL = """/*
 * KSU_HWID_LOCK: 主板 ID 绑定（构建时生成，勿手改）。
 *
 * 白名单为空时不做任何限制；非空时，只允许列表内的 HWID 使用 KernelSU。
 */
#ifndef __KSU_HWID_LOCK_H
#define __KSU_HWID_LOCK_H

#include <linux/of.h>
#include <linux/string.h>
#include <linux/types.h>

extern char *saved_command_line;

static const char *const ksu_hwid_whitelist[] = {
%s};

#define KSU_HWID_COUNT ((int)(sizeof(ksu_hwid_whitelist) / sizeof(ksu_hwid_whitelist[0])))

static inline bool ksu_hwid_match(const char *hay)
{
    int i;

    if (!hay)
        return false;

    for (i = 0; i < KSU_HWID_COUNT; i++) {
        if (ksu_hwid_whitelist[i][0] && strstr(hay, ksu_hwid_whitelist[i]))
            return true;
    }

    return false;
}

static inline bool ksu_hwid_allowed(void)
{
    struct device_node *np;
    const char *prop;

    /* 白名单为空：不限制 */
    if (KSU_HWID_COUNT == 0)
        return true;

    if (saved_command_line && ksu_hwid_match(saved_command_line))
        return true;

    np = of_find_node_by_path("/");
    if (np) {
        prop = of_get_property(np, "serial-number", NULL);
        if (ksu_hwid_match(prop))
            return true;
    }

    np = of_find_node_by_path("/chosen");
    if (np) {
        prop = of_get_property(np, "bootargs", NULL);
        if (ksu_hwid_match(prop))
            return true;
    }

    return false;
}

#endif /* __KSU_HWID_LOCK_H */
"""

GATE = """    /* KSU_HWID_LOCK: 非白名单设备不授予任何 KSU 能力 */
    if (!ksu_hwid_allowed()) {
        static bool warned;

        if (!warned) {
            warned = true;
            pr_err("ksu: device not in HWID whitelist, KernelSU disabled\\n");
        }
        return 0;
    }

"""


def read_list(env_value):
    items = []
    for raw in (env_value or "").replace(",", "\n").split("\n"):
        s = raw.strip()
        if s and not s.startswith("#"):
            items.append(s)
    return items


def generate_header(items, path):
    body = "".join('    "%s",\n' % s.replace('"', '') for s in items)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER_TMPL % body)
    print("hwid 白名单 %d 条 -> %s" % (len(items), path))


def inject(path, marker_include_after):
    text = open(path, encoding="utf-8", errors="surrogateescape").read()
    if MARK + "_GATE" in text:
        print("%s 已含 HWID 门控，跳过" % path)
        return 0

    if marker_include_after is None:
        text = '#include "hwid_lock.h"\n' + text
    elif marker_include_after in text:
        text = text.replace(
            marker_include_after,
            marker_include_after + '#include "hwid_lock.h"\n',
            1,
        )
    else:
        print("%s 缺少 include 锚点" % path, file=sys.stderr)
        return 2

    sig = "int ksu_handle_setresuid("
    i = text.find(sig)
    if i < 0:
        print("%s 未找到 ksu_handle_setresuid" % path, file=sys.stderr)
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

    ins = brace + 1
    text = text[:ins] + "\n" + GATE + text[ins:].lstrip("\n")

    text = text.replace("#include \"hwid_lock.h\"\n",
                        "#include \"hwid_lock.h\" /* %s_GATE */\n" % MARK, 1)

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
        print("未找到含 ksu_handle_setresuid 的 hook 文件，跳过 HWID 绑定", file=sys.stderr)
        return 2

    items = read_list(os.environ.get("HWID_WHITELIST", ""))
    header = os.path.join(os.path.dirname(target), "hwid_lock.h")
    generate_header(items, header)

    if not items:
        print("白名单为空，仅生成头文件，不注入门控（不限制）")
        return 0

    return inject(target, None)


if __name__ == "__main__":
    sys.exit(main())
