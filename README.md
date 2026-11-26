# cf-pixiv-android

安卓端 Pixiv 图片加速：**Cloudflare DoH(HTTP/3) 本地 DNS + 有限路由 VPN + 本地 nginx 反代 i.pximg.net**。

不需要 root，不影响其他 App 上网。

## 组成部分

| 组件 | 说明 |
|---|---|
| `libdoh3dns.so` | Go 写的本地 DNS：上游只走 `https://cloudflare-dns.com/dns-query` 的 **HTTP/3/QUIC**（无 TCP 回退），给 HTTPS/SVCB 记录注入 `alpn="h3"`，把 `i.pximg.net` 劫持到 `10.111.222.3` |
| `libnginx.so` | 交叉编译的 nginx 1.29.4（aarch64 Android，静态链接 OpenSSL/PCRE2/zlib）：`127.0.0.1:8444` 提供 TLS 反代，`127.0.0.1:8443` 提供明文反代 |
| `DnsVpnService` | 只接管 DNS 与 `i.pximg.net:443` 的 VPN：路由仅 `10.111.222.0/24`，在 TUN 里用用户态 TCP 把 `10.111.222.3:443` 转到 `127.0.0.1:8444`，**无需 root 即可让客户端以为连的是 443** |
| CA | 打包一套自签 CA + `i.pximg.net` 证书，App 内可导出 `ca.crt` 供系统信任 |

## 工作流程

1. 点「启动」：拉起本地 DNS（DoH3 上游）与 nginx 反代
2. 点「VPN」：系统 DNS 指向 `10.111.222.1`，`i.pximg.net:443` 被 TUN 截获转给本地反代
3. 装 CA：App 内「导出CA」→ 设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书
4. 用系统浏览器（Chrome / Edge / Firefox）打开 Pixiv，图片自动走本地反代

## 为什么不会拖垮其他 App

VPN 只 `addRoute("10.111.222.0", 24)`：只有被 DNS 劫持到该网段的域名才会进 TUN，其余流量完全走系统原网络。Watt Toolkit 用的是 `AddRoute("0.0.0.0", 0)` 全局接管，它的 tun2http + 本地代理一旦卡住就全网断网。

## i.pximg.net 反代 IP 与方法

参考 [mashirozx/Pixiv-Nginx](https://github.com/mashirozx/Pixiv-Nginx)：

- 上游 IP 列表来自 [conf/site-pixiv.conf](https://github.com/mashirozx/Pixiv-Nginx/blob/main/conf/site-pixiv.conf) 的 `upstream i-pximg-net`：
  `210.140.139.131~138`、`210.140.139.149~150`，`least_conn` + `keepalive 16`
- 反代方法同文件的 `server_name *.pximg.net` 块：`Host: i.pximg.net`、`Referer: https://www.pixiv.net/`
- **关键**：空 SNI，组合自
  [conf/shared-proxy-params-empty-sni.conf](https://github.com/mashirozx/Pixiv-Nginx/blob/main/conf/shared-proxy-params-empty-sni.conf)
  与 [conf/shared-proxy-params-1.conf](https://github.com/mashirozx/Pixiv-Nginx/blob/main/conf/shared-proxy-params-1.conf)

实测：对上游发 `SNI=i.pximg.net` 的 TLS 握手会被直接 reset；不带 SNI 才能完成 TLS 1.3 握手（证书 `CN=pximg.net`）。

## 关于 h3 与浏览器

Pixiv 主站必须走 HTTP/3 才能访问（TCP/443 会被重置）。DNS 始终给 HTTPS 记录注入 `alpn="h3"`：

- Chrome / Edge（Chromium）：会查询 HTTPS 记录，直接走 h3
- Firefox：会查询 HTTPS 记录，可在 `about:config` 调整
- **Android WebView 不会查询 HTTPS 记录**，所以 WebView 内（含本 App 曾经的「内置访问」）在 TCP 被墙时无法打开主站。因此 App 已移除内置 WebView，统一改用系统浏览器

App 启动时用 DNS 核心的 `-probe` 实打实发一次 HTTP/3 查询（UDP/443 → Cloudflare）判断当前网络是否允许 QUIC：

- 可用：状态栏显示「QUIC : 可用，Pixiv 主站走 h3」
- 不可用：显示「不可用（UDP/443 被阻断，Pixiv 主站会连接重置）」，此时 `i.pximg.net` 反代仍可用，但主站打不开

## 诊断

运行时目录在 `/storage/emulated/0/Android/data/cn.hugengron/files/core/`（部分系统需用 MT 管理器进入）：

- `core.log`：DNS / nginx 进程日志
- `error.log`：nginx 错误
- `vpn.log`：VPN 收发统计（含 `dns i.pximg.net t=1 -> ...`、`dns www.pixiv.net t=65 -> ...`）
- `ca.crt`：CA 证书

App 内「日志」按钮可直接查看并分享，无需文件管理器。

## 构建

依赖：JDK 17、Android SDK（platform-35、platform-tools、build-tools 35.0.0、NDK r27c）、Go 1.27、Gradle 9.2.x。

> AGP 8.13 不能配 Gradle 9.6+（内部 API 被移除），请勿用更新的 Gradle。

```bash
./build.sh
```

- `core/`：Go 源码，`GOOS=android GOARCH=arm64 CGO_ENABLED=0` 编译成 `jniLibs/arm64-v8a/libdoh3dns.so`
- `tools/build-nginx.sh`：编译 OpenSSL → PCRE2 → nginx。为适配 bionic 做了三处源码补丁：运行型特性检测改编译型、`sizeof` 用 LP64 预置、`EPOLL*` 宏比较改为常量

## 已验证 / 未验证

已验证（本机 x86_64）：

- DoH3 上游可用，`alpn=h3` 正确注入，`i.pximg.net` 劫持到 `10.111.222.3`
- nginx 配置 `nginx -t` 通过；TLS 反代返回 200；证书链对 CA 校验通过
- 空 SNI 反代链路可用
- 边缘 IP 仅使用 IPv4（避免设备无 IPv6 路由时 `no route to host`）

真机已验证：Edge 经 VPN 解析并走 h3 访问 Pixiv 成功；i.pximg.net 劫持生效。

未验证：不同 ROM 的用户 CA 信任策略、第三方 App 是否信任用户 CA。

## 已知限制

- 上游 IP 会随 Pixiv 调度变化，失效时改 `Core.kt` 里的 `upstream` 列表
- 系统「私人 DNS」（DoT）会绕过本 App 的 DNS，需要关闭
- Android 7+ 用户 CA 默认只被 Chromium 系浏览器信任，其他 App 需自行声明
- `shouldInterceptRequest` 拿不到 POST body，因此不再走拦截方案
