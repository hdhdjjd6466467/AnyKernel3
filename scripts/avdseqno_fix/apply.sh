#!/usr/bin/env bash
# avd.seqno 归一化：/sys/fs/selinux/access 回复里第 5 个字段（avd.seqno）固定为 0。
#
# 报告里 [✖ DANGER] SELinux 的唯一判据是：
#   DirtySepolicy 2.2 compatibility=WARNING / Non-initial avdSeqNo; avdSeqNo=5
# avd.seqno 就是 policy->latest_granting：
#   1（初始）+ 策略加载次数 + 开机期间写 SELinux 布尔值的次数
# 同一份报告里 status.policyload=0、Permissive domains: None、KSU 类型全 INVALID，
# 说明没有策略注入，5 只是布尔写入推进的代际。把回复里这个字段压回 0，
# 检测器拿到的就是初始 epoch；allowed/denied 判定一个字节不动。
#
# 只改 selinuxfs 的这条查询回复（sel_write_access），不碰 compute_av / avc / policy。
set -euo pipefail

KROOT="${KERNEL_ROOT:-.}"
F="$KROOT/common/security/selinux/selinuxfs.c"

fail() {
  if [ "${SKIP_INCOMPATIBLE:-false}" = "true" ]; then
    echo "::warning title=avd.seqno 归一化已跳过::$1"
    exit 0
  fi
  echo "::error::$1"
  exit 1
}

[ -f "$F" ] || fail "未找到 $F"

if grep -q KSU_AVDSEQNO_ZERO "$F"; then
  echo "selinuxfs.c 已含 avd.seqno 归一化，跳过"
  exit 0
fi

python3 - "$F" <<'PYEOF'
import re, sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="surrogateescape").read()

m = re.search(r"sel_write_access\(struct file[^)]*\)\s*\{", text)
if not m:
    sys.exit("找不到 sel_write_access 定义")
start = m.start()
depth = 0
i = text.find("{", start)
while i < len(text):
    if text[i] == "{":
        depth += 1
    elif text[i] == "}":
        depth -= 1
        if depth == 0:
            break
    i += 1
if depth != 0:
    sys.exit("sel_write_access 花括号不平衡")
end = i + 1
body = text[start:end]

if "avd.seqno" not in body:
    sys.exit("回复格式里没有 avd.seqno（上游结构可能已变化）")

new_body = body.replace(
    "avd.seqno",
    "0 /* KSU_AVDSEQNO_ZERO: 归一化代际，避免布尔写入推进的 avdSeqNo 被当成策略注入 */",
)
if new_body == body:
    sys.exit("替换未生效")

open(path, "w", encoding="utf-8", errors="surrogateescape", newline="").write(
    text[:start] + new_body + text[end:]
)
print("  selinuxfs.c: sel_write_access 回复中的 avd.seqno -> 0")
PYEOF

grep -q KSU_AVDSEQNO_ZERO "$F" || fail "归一化补丁校验失败"
echo "avd.seqno 归一化完成：access 节点回复的第 5 字段恒为 0"
