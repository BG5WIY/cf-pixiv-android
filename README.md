# cf-pixiv-android

安卓端 Pixiv 图片加速：**Cloudflare DoH3 本地 DNS + 本地 nginx 反代 i.pximg.net**。

## 组成部分

| 组件 | 说明 |
|---|---|
| `libdoh3dns.so` | Go 写的本地 DNS（复用 `~/cf-doh3-dns` 的逻辑）：上游只走 `https://cloudflare-dns.com/dns-query` 的 **HTTP/3/QUIC**，无 TCP 回退；给 HTTPS/SVCB 记录注入 `alpn="h3"`；把 `i.pximg.net` 劫持到 `127.0.0.1` |
| `libnginx.so` | 交叉编译的 nginx 1.29.4（aarch64 Android，静态链接 OpenSSL 3.5.4 / PCRE2 10.46 / zlib），监听 `127.0.0.1:8443` 反代 `i.pximg.net` |
| `DnsVpnService` | 只接管 DNS 的 VPN：系统 DNS 指向 `10.111.222.1`，TUN 内 UDP/53 转给本地 Go DNS，**无需 root** |
| `PixivClient` | WebView 出口改写：网页里所有 `i.pximg.net` 请求改写到 `127.0.0.1:8443`，这是 443 不可用时的兜底 |

## i.pximg.net 反代 IP 与方法

来自本机 `~/Pixiv-Nginx/conf/site-pixiv.conf` 的探测结果：

- 上游：`upstream i-pximg-net { least_conn; 210.140.139.131~138、149~150:443; keepalive 16; }`
- 方法：`proxy_pass https://i-pximg-net`，`Host: i.pximg.net`，`Referer: https://www.pixiv.net/`
- **关键**：原项目用 `shared-proxy-params-empty-sni.conf` 里的 `proxy_ssl_name ""`（空 SNI）。

实测：对上游发 `SNI=i.pximg.net` 的 TLS 握手会被直接 reset（SNI 阻断）；
不带 SNI 则 TLS 1.3 握手成功，证书为 `CN=pximg.net`。所以 App 里的 nginx 用空 SNI。

## 两条工作路径

1. **系统级**（需要 root 才能监听 443）：DNS 把 `i.pximg.net` 劫持到 `127.0.0.1`，
   其他 App 也走本地反代。
2. **内置浏览器**（默认，无需 root）：App 内 WebView 打开 Pixiv，
   `shouldInterceptRequest` 把 `i.pximg.net` 改写成 `127.0.0.1:8443`。

## 构建

依赖：JDK 17、Android SDK（platform-35、build-tools 35.0.0、NDK r27c）、Go 1.27。

```bash
./build.sh
```

- `core/`：Go DNS 源码，`GOOS=android GOARCH=arm64 CGO_ENABLED=0` 编译成
  `jniLibs/arm64-v8a/libdoh3dns.so`。
- `tools/build-nginx.sh`：编译 OpenSSL → PCRE2 → nginx。为适配 bionic 做了三处源码补丁：
  运行型特性检测改编译型、`sizeof` 用 LP64 预置、`EPOLL*` 宏比较改为常量。
- 产物 `cf-pixiv-android-arm64.apk`（约 9.9 MB，debug 签名）。

## 使用

1. 安装 APK（arm64 设备，Android 9+）。
2. 点「启动」：拉起 Go DNS（`127.0.0.1:5353`）与 nginx（`127.0.0.1:8443`），
   日志在 `files/core/core.log`、`files/core/error.log`。
3. 点「VPN」授权后，系统解析走 Cloudflare DoH3。
4. 点「Pixiv」在内置 WebView 打开，图片经本地 nginx 反代。

## 已验证 / 未验证

已验证（本机 x86_64）：

- Go DNS 的 DoH3 上游可用：`-probe example.com` 返回 Cloudflare 结果。
- nginx 配置语法 `nginx -t` 通过。
- 空 SNI 反代链路：本机 nginx + 同样的 upstream/Host/Referer 能拿到 Pixiv 响应。

未验证：

- 未在真机/arm64 设备上运行（本机无 arm64 模拟器，waydroid 为 x86_64 且无 root）。
- nginx/Go 以 ELF 形式放在 `jniLibs`、从 `nativeLibraryDir` 执行，依赖
  `android:extractNativeLibs="true"` 的解压可执行权限；这是常见做法但需真机确认。
- WebView 中 Pixiv 的登录/API 行为未测试。

## 已知限制

- 上游 IP 会随 Pixiv 调度变化，失效时改 `Core.kt` 里的 `upstream` 列表。
- 非 root 无法监听 443，只能走内置浏览器路径。
- 系统「私人 DNS」会绕过本 App 的 DNS，需要关闭。
