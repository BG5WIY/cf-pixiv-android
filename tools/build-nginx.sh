#!/usr/bin/env bash
# 交叉编译 nginx (aarch64 Android)，静态链接 OpenSSL/PCRE2/zlib
set -euo pipefail

SDK=${ANDROID_HOME:-$HOME/android-sdk}
NDK=${NDK_DIR:-$SDK/ndk/27.2.12479018}
API=28
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$SDK/out
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$API-clang
CXX=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$API-clang++
AR=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
RANLIB=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib
STRIP=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
export CC CXX AR RANLIB STRIP
export PATH=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

[ -x "$CC" ] || { echo "找不到 NDK clang: $CC" >&2; exit 1; }
mkdir -p "$OUT"

cd "$SRC/nginx-1.29.4"
if [ -f objs/nginx ]; then
  echo "==> nginx 已构建，跳过"
else
  echo "==> configure"
  ./configure \
    --crossbuild=Linux::aarch64 \
    --prefix=/nginx \
    --conf-path=/nginx/nginx.conf \
    --with-cc="$CC" \
    --with-cc-opt="-O2 -fPIC -I$OUT/openssl-aarch64/include -I$OUT/pcre2-aarch64/include" \
    --with-ld-opt="-L$OUT/openssl-aarch64/lib -L$OUT/pcre2-aarch64/lib -lssl -lcrypto -lpcre2-8 -L$OUT/lib -lpthread -static-libgcc -Wl,-z,max-page-size=16384" \
    --with-zlib="$SRC/zlib-1.3.1" \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-threads \
    --with-http_realip_module \
    --with-http_gzip_static_module \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_memcached_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_grpc_module \
    > "$OUT/nginx-configure.log" 2>&1 || { echo "configure 失败："; tail -30 "$OUT/nginx-configure.log"; exit 1; }
  echo "==> make"
  make -j15 > "$OUT/nginx-make.log" 2>&1 || { echo "make 失败："; tail -30 "$OUT/nginx-make.log"; exit 1; }
fi

file objs/nginx
"$STRIP" -o "$OUT/nginx-arm64" objs/nginx
file "$OUT/nginx-arm64"
ls -la "$OUT/nginx-arm64"
echo "==> 完成: $OUT/nginx-arm64"
