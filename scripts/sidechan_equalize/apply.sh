#!/usr/bin/env bash
# 时序等时化（针对 Duck Detector 的 "KSU context timing anomaly"）：
# 报告里的探针 ksu_types timing with invalid types (setprocattr) 比较两条写：
#   A = u:r:ksu:s0（KSU 类型，藏在 backup 策略里）
#   B = 同长度但类型不存在的非法 context
# 当前 selinux_hide 对 A 返回 -EAGAIN 并触发回退重解析，对 B 在 symtab 阶段就 -EINVAL，
# 两条路径深度不同，于是方向计数长期偏一边（6.12.69 上 A<B 10541 vs 阈值 8877）。
#
# 修法：KSU 类型直接在类型阶段按「未知类型」处理（-EINVAL），不再进回退路径；
# 只有代际未知（type_is_original < 0）才保留 -EAGAIN 重试。
# 结果面不变：两种写法对应用层都是 EINVAL，隐藏语义不变。
set -euo pipefail

KSU_DIR="${1:-KernelSU}"
F="$KSU_DIR/kernel/feature/selinux_hide.c"

fail() {
  if [ "${SKIP_INCOMPATIBLE:-false}" = "true" ]; then
    echo "::warning title=时序等时化补丁跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -f "$F" ] || fail "未找到 $F"
if grep -q KSU_SIDECHAN_EQ_EINVAL "$F"; then
  echo "selinux_hide.c 已含时等化补丁，跳过"
  exit 0
fi

python3 - "$F" <<'PYEOF'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

OLD = (
    "    type_is_original = ksu_type_is_original(live_pol, policy_generation, typdatum->value);\n"
    "    if (type_is_original <= 0) {\n"
    "        rc = -EAGAIN;\n"
    "        goto out;\n"
    "    }\n"
)

NEW = (
    "    type_is_original = ksu_type_is_original(live_pol, policy_generation, typdatum->value);\n"
    "    if (type_is_original < 0) {\n"
    "        rc = -EAGAIN;\n"
    "        goto out;\n"
    "    }\n"
    "    if (!type_is_original) {\n"
    "        /* KSU_SIDECHAN_EQ_EINVAL: KSU 类型按未知类型处理，避免回退重解析造成时序差 */\n"
    "        rc = -EINVAL;\n"
    "        goto out;\n"
    "    }\n"
)

if OLD not in text:
    print("  SKIP: 未找到 type_is_original <= 0 判定块")
    sys.exit(0)

text = text.replace(OLD, NEW, 1)
open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(text)
print("  selinux_hide.c: KSU 类型改为类型阶段 EINVAL")
PYEOF

grep -q KSU_SIDECHAN_EQ_EINVAL "$F" || fail "补丁校验失败"
echo "时序等时化完成：KSU 类型与未知类型在类型阶段返回同一错误"