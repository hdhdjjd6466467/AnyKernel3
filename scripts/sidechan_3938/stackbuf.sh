#!/usr/bin/env bash
# 移植 PR #3938 的“栈缓冲”做法（0ctobot）：
#   128 字节以内的 context 不再 kmemdup_nul/kfree，改用栈上缓冲。
# 作用在两条 setprocattr/access 都会走到的函数：
#   security_context_to_sid_live()        —— attr/current 写入路径（报告探针就是这个）
#   security_context_to_sid_with_policy() —— access 节点查询路径
# 语义不变：长度超限时仍回退到 kmemdup_nul，只是省掉短 context 的一次分配+释放。
set -euo pipefail

KSU_DIR="${1:-KernelSU}"
F="$KSU_DIR/kernel/feature/selinux_hide.c"

fail() {
  if [ "${SKIP_INCOMPATIBLE:-false}" = "true" ]; then
    echo "::warning title=3938 栈缓冲移植跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -f "$F" ] || fail "未找到 $F"
if grep -q KSU_SIDECHAN_3938_STACK "$F"; then
  echo "selinux_hide.c 已含 3938 栈缓冲移植，跳过"
  exit 0
fi

python3 - "$F" <<'PYEOF'
import re, sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

MARK = "KSU_SIDECHAN_3938_STACK"


def function_bounds(src, name):
    # 必须匹配“定义”（参数列表后直接跟 {），否则会命中前面的原型声明
    m = re.search(r"static\s+int\s+" + name + r"\([^;]*\)\s*\{", src, re.S)
    if not m:
        return None
    i = src.find("{", m.start())
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return m.start(), j + 1
        j += 1
    return None


def patch_func(src, name):
    b = function_bounds(src, name)
    if not b:
        return src, "找不到函数 " + name
    s, e = b
    body = src[s:e]
    if MARK in body:
        return src, None

    alloc = re.search(r"    scontext2 = kmemdup_nul\(scontext, scontext_len, ([A-Za-z_]+)\);\n"
                      r"    if \(!scontext2\)\n        return -ENOMEM;\n", body)
    if not alloc:
        return src, name + " 中未找到 scontext2 = kmemdup_nul 分配块"
    gfp = alloc.group(1)
    new_alloc = (
        "    /* " + MARK + ": 短 context 走栈缓冲，免掉一次 kmalloc/kfree（PR #3938 做法） */\n"
        "    if (scontext_len < sizeof(scontext2_buf)) {\n"
        "        scontext2 = scontext2_buf;\n"
        "        memcpy(scontext2, scontext, scontext_len);\n"
        "        scontext2[scontext_len] = '\\0';\n"
        "    } else {\n"
        "        scontext2 = kmemdup_nul(scontext, scontext_len, " + gfp + ");\n"
        "        if (!scontext2)\n"
        "            return -ENOMEM;\n"
        "    }\n"
    )
    body = body[:alloc.start()] + new_alloc + body[alloc.end():]

    # 声明栈缓冲
    decl = re.search(r"    char \*scontext2;\n", body)
    if not decl:
        return src, name + " 中未找到 char *scontext2; 声明"
    body = body[:decl.start()] + "    char scontext2_buf[128] __aligned(sizeof(long));\n" + body[decl.start():]

    # 释放处加判断
    body = re.sub(r"\n    kfree\(scontext2\);",
                  "\n    if (scontext2 != scontext2_buf)\n        kfree(scontext2);", body)

    return src[:s] + body + src[e:], None


for fn in ("security_context_to_sid_live", "security_context_to_sid_with_policy"):
    text, err = patch_func(text, fn)
    if err:
        print("  SKIP: " + err)
        sys.exit(0)

if MARK not in text:
    print("  SKIP: 未产生任何修改")
    sys.exit(0)

open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(text)
print("  selinux_hide.c: 两个解析函数已改用 128B 栈缓冲")
PYEOF

grep -q KSU_SIDECHAN_3938_STACK "$F" || fail "移植校验失败"
echo "3938 栈缓冲移植完成"