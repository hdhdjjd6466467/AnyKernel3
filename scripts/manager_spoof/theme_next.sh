#!/usr/bin/env bash
# KernelSU-Next 管理器换肤：牢大爱肘击
# 用法: theme_next.sh <manager 目录>
set -euo pipefail
M="${1:?usage: theme_next.sh <manager dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON="$HERE/icon.png"; BG="$HERE/bg.webp"; RES="$M/app/src/main/res"
[ -d "$RES" ] || { echo "::error::找不到 $RES"; exit 1; }

# 1) 干掉自适应图标，换成位图
rm -f "$RES"/mipmap-anydpi/ic_launcher.xml "$RES"/mipmap-anydpi-v26/ic_launcher.xml 2>/dev/null || true
for d in "$RES"/mipmap-*dpi; do
  cp "$ICON" "$d/ic_launcher.png"
done

# 2) 应用名
for f in "$RES"/values*/strings.xml; do
  [ -f "$f" ] || continue
  sed -i "s#<string name=\"app_name\"[^>]*>[^<]*</string>#<string name=\"app_name\" translatable=\"false\">牢大爱肘击</string>#" "$f"
done
grep -q "牢大爱肘击" "$RES/values/strings.xml" || { echo "::error::app_name 替换失败"; exit 1; }

# 3) 背景图（能挂上就挂，挂不上留警告）
cp "$BG" "$RES/drawable/app_bg.webp"
python3 - "$RES" <<'PY'
import glob, os, sys
res = sys.argv[1]
patched = False
for path in glob.glob(os.path.join(res, "values*", "themes.xml")):
    s = open(path, encoding="utf-8").read()
    if "app_bg" in s:
        patched = True; continue
    import re
    m = re.search(r'<style name="Theme\.[^"]+"[^>]*>\n', s)
    if not m:
        continue
    s = s[:m.end()] + '        <item name="android:windowBackground">@drawable/app_bg</item>\n' + s[m.end():]
    open(path, "w", encoding="utf-8").write(s)
    patched = True
print("背景已挂到主题" if patched else "::warning::未找到主题样式，背景未挂")
PY

echo "KernelSU-Next 换肤完成：名称/图标/背景"