#!/usr/bin/env bash
# 一键构建：Go DNS 核心 + nginx(aarch64) + APK
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
SDK=${ANDROID_HOME:-$HOME/android-sdk}
OUT=$SDK/out
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}
GRADLE=${GRADLE:-$(ls -d "$HOME"/.gradle/wrapper/dists/gradle-9.2.1-bin/*/gradle-9.2.1/bin/gradle | head -1)}

echo "== Go DNS 核心 (android/arm64)"
(cd "$ROOT/core" && GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w" -o "$OUT/libdoh3dns.so" .)

echo "== nginx (aarch64)"
[ -x "$OUT/nginx-arm64" ] || "$ROOT/tools/build-nginx.sh"

echo "== 汇总到 jniLibs"
mkdir -p "$ROOT/app/src/main/jniLibs/arm64-v8a"
cp "$OUT/libdoh3dns.so" "$ROOT/app/src/main/jniLibs/arm64-v8a/"
cp "$OUT/nginx-arm64" "$ROOT/app/src/main/jniLibs/arm64-v8a/libnginx.so"

echo "== Gradle assembleDebug"
cd "$ROOT"
JAVA_HOME=$JAVA_HOME ANDROID_HOME=$SDK ANDROID_SDK_ROOT=$SDK \
  "$GRADLE" assembleDebug --no-daemon

echo "APK: $ROOT/app/build/outputs/apk/debug/app-debug.apk"
