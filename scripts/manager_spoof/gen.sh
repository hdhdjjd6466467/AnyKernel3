#!/usr/bin/env bash
# KernelSU-Next v3.4.2 的 spoof 思路：随机三段小写单词做包名，版本/名称加后缀，
# 让管理器在包名维度上不再命中 com.*.ksunext / com.sukisu.nova 这类固定特征。
# 另外每次构建生成独立 keystore，签名证书也不再与上游管理器一致。
set -euo pipefail

w() { tr -dc "a-z" </dev/urandom | head -c6; }
W1=$(w); W2=$(w); W3=$(w)

PKG="com.${W1}.${W2}.${W3}"
NAME="牢大爱肘击"
KS="$GITHUB_WORKSPACE/manager-spoof.jks"
KSPASS=$(tr -dc "A-Za-z0-9" </dev/urandom | head -c16)

keytool -genkeypair -v -keystore "$KS" -storepass "$KSPASS" -keypass "$KSPASS" \
  -alias spoof -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Suki Manager, OU=Spoof, O=Spoof, L=Spoof, S=Spoof, C=CN" >/dev/null 2>&1

{
  echo "SPOOF_PKG=$PKG"
  echo "SPOOF_NAME=$NAME"
  echo "KEYSTORE_FILE=$KS"
  echo "KEYSTORE_PASSWORD=$KSPASS"
  echo "KEY_ALIAS=spoof"
  echo "KEY_PASSWORD=$KSPASS"
} >> "$GITHUB_ENV"

echo "spoof 包名: $PKG"
echo "spoof 名称: $NAME"