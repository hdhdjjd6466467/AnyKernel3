#!/usr/bin/env bash
# 主板 ID（HWID）绑定 —— 把白名单编进内核，非白名单设备不授予 KSU 能力。
# 白名单来自环境变量 HWID_WHITELIST（换行或逗号分隔）；为空则不限制。
# 调用方工作目录需为 KERNEL_ROOT。
set -eo pipefail

KSU_DIR="${1:-KernelSU}"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SELF_DIR/patch_hwid.py" "$KSU_DIR"
rc=$?
if [ "$rc" = "2" ]; then
  if [ "$SKIP_INCOMPATIBLE" = "true" ]; then
    echo "::warning title=HWID 绑定已跳过::未找到可用锚点（上游结构可能已变化）"
    exit 0
  fi
  echo "::error::HWID 绑定锚点不匹配"
  exit 1
fi
exit "$rc"