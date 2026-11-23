#!/usr/bin/env bash
# 把管理器换成「牢大爱肘击」皮肤：
#   图标 = scripts/manager_spoof/icon.png
#   启动图/背景 = scripts/manager_spoof/bg.webp
# 用法: theme.sh <manager 目录>（即 sukisu/manager）
set -euo pipefail

M="${1:?usage: theme.sh <manager dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON="$HERE/icon.png"
BG="$HERE/bg.webp"
RES="$M/app/src/main/res"

[ -d "$RES" ] || { echo "::error::找不到 $RES"; exit 1; }
[ -f "$ICON" ] || { echo "::error::缺 icon.png"; exit 1; }
[ -f "$BG" ] || { echo "::error::缺 bg.webp"; exit 1; }

# 1) 启动图标：清掉自适应图标 XML 与旧 webp，所有密度统一换成给定 PNG
rm -f "$RES"/mipmap-anydpi-v26/ic_launcher*.xml
for d in "$RES"/mipmap-*dpi; do
  rm -f "$d"/ic_launcher.webp "$d"/ic_launcher_round.webp "$d"/ic_launcher.png "$d"/ic_launcher_round.png
  cp "$ICON" "$d/ic_launcher.png"
  cp "$ICON" "$d/ic_launcher_round.png"
done

# 2) 启动图 / 应用背景
rm -f "$RES"/drawable/ic_launcher_splash.xml
cp "$BG" "$RES/drawable/ic_launcher_splash.webp"
cp "$BG" "$RES/drawable/app_bg.webp"

# 3) 基础主题加 windowBackground，让窗口底色也是这张图
python3 - "$RES" <<'PY'
import os, sys
res = sys.argv[1]
targets = [
    (os.path.join(res, "values", "themes.xml"), '    <style name="Theme.KernelSU" parent="android:Theme.Material.Light.NoActionBar">\n'),
    (os.path.join(res, "values-night", "themes.xml"), '    <style name="Theme.KernelSU" parent="android:Theme.Material.NoActionBar">\n'),
]
for path, anchor in targets:
    if not os.path.isfile(path):
        continue
    s = open(path, encoding="utf-8").read()
    if "app_bg" in s or anchor not in s:
        continue
    s = s.replace(anchor, anchor + '        <item name="android:windowBackground">@drawable/app_bg</item>\n', 1)
    open(path, "w", encoding="utf-8").write(s)
    print("主题已加 windowBackground: " + path)
PY

echo "皮肤应用完成：图标 + 启动图 + 主题背景"