#!/usr/bin/env bash
# attr/current 读取侧伪装 —— 调用方（调用方工作目录需为 KERNEL_ROOT）
# 具体实现见 patch_attr.py：KSU main 分支走 lsm_hook，builtin 分支改内核
# security/selinux/hooks.c 的 selinux_getprocattr。
set -eo pipefail

KSU_DIR="${1:-KernelSU}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
  if [ "$SKIP_INCOMPATIBLE" = "true" ]; then
    echo "::warning title=attr/current 伪装补丁已跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

python3 "$SELF_DIR/patch_attr.py" "$KSU_DIR"
rc=$?
if [ "$rc" = "2" ]; then
  fail "attr/current 伪装锚点不匹配（上游结构可能已变化）"
elif [ "$rc" != "0" ]; then
  fail "attr/current 伪装执行失败（rc=$rc）"
fi
echo "attr/current 伪装完成"