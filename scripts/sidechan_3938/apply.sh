#!/usr/bin/env bash
# 单独应用 tiann/KernelSU PR #3938（0ctobot）的方案，不与 A/B/C 混用：
#   - string_to_context_struct() 退回单策略解析（stock 形状）
#   - 先解析 backup 策略，成功后才动 live 策略的 sidtab
#   - 128 字节以内的 context 用栈缓冲，免掉 kmemdup/kfree
# 目的：把「双解析 + 双 SID 查询」的固定开销和失败路径的额外解析压下去。
#
# 用法: apply.sh [KernelSU 目录]（工作目录需为 $KERNEL_ROOT）
set -euo pipefail

KSU_DIR="${1:-KernelSU}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$SRC/pr3938.patch"
F="$KSU_DIR/kernel/feature/selinux_hide.c"

fail() {
  if [ "${SKIP_INCOMPATIBLE:-false}" = "true" ]; then
    echo "::warning title=3938 补丁跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -f "$F" ] || fail "未找到 $F"
[ -f "$PATCH" ] || fail "未找到补丁 $PATCH"

if grep -q KSU_SIDECHAN_3938 "$F"; then
  echo "selinux_hide.c 已应用 3938 方案，跳过"
  exit 0
fi

echo "应用 PR #3938（先 backup 再 live + 栈缓冲）..."
if git -C "$KSU_DIR" apply --check -p1 "$PATCH" 2>/dev/null; then
  git -C "$KSU_DIR" apply -p1 "$PATCH"
elif (cd "$KSU_DIR" && patch -p1 -F 3 --forward < "$PATCH" >/dev/null 2>&1); then
  echo "  用 patch -F3 应用（有模糊匹配）"
else
  fail "补丁与当前 selinux_hide.c 不匹配（上游已改结构）"
fi

grep -q scontext2_onstack "$F" || fail "应用后未找到 scontext2_onstack，补丁可能没落地"
grep -q retry_live "$F" || fail "应用后未找到 retry_live 标签"

# 幂等标记
sed -i "1i /* KSU_SIDECHAN_3938: tiann/KernelSU PR #3938 applied */" "$F"
echo "3938 方案已应用：单策略解析 + backup 优先 + 128B 栈缓冲"