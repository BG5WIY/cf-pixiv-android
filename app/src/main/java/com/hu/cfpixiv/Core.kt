package com.hu.cfpixiv

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit

/**
 * 管理两个原生进程：
 *  - libdoh3dns.so : Cloudflare DoH(HTTP/3) 上游的本地 DNS，hijack i.pximg.net
 *  - libnginx.so   : 127.0.0.1 上的 i.pximg.net 反代
 */
class Core(private val ctx: Context) {

    val dir = File(ctx.filesDir, "core").apply { mkdirs() }
    private val nativeDir = ctx.applicationInfo.nativeLibraryDir
    private val logFile = File(dir, "core.log")

    private var dns: Process? = null
    private var web: Process? = null

    var dnsPort = 5353
        private set
    var proxyPort = 8443
        private set

    fun isRunning() = dns?.isAlive == true || web?.isAlive == true

    /** 最近一次启动时探测到的 QUIC(UDP/443) 可用性 */
    var quicAvailable: Boolean? = null
        private set

    fun start(): String {
        stop()
        val sb = StringBuilder()
        copyAsset("nginx/mime.types")
        if (!portFree(proxyPort)) proxyPort = freePort(18443)
        writeNginxConf()

        val dnsBin = File(nativeDir, "libdoh3dns.so")
        val nginxBin = File(nativeDir, "libnginx.so")
        if (!dnsBin.exists() || !nginxBin.exists()) {
            return "原生二进制缺失：${dnsBin.exists()} ${nginxBin.exists()}"
        }

        // 可用性判断:Pixiv 主站必须走 HTTP/3(TCP/443 会被重置),所以 h3 标记始终开启;
        // 这里探测的是"本机到 Cloudflare 的 UDP/443 是否通",通了才说明 WebView 的 h3 有戏。
        // bind 443 的权限只看端口号,与绑在哪个地址(含 TUN 的 10.x)无关;非 root 一般拿不到
        val can443 = runCatching { ServerSocket(443).use { } }.isSuccess
        sb.append("443  : ")
            .append(if (can443) "可绑定（有特权）" else "不可绑定（非 root，反代走 $proxyPort）")
            .append('\n')

        quicAvailable = probeQuic(dnsBin)
        sb.append("QUIC : ")
            .append(
                if (quicAvailable == true) "可用，Pixiv 主站走 h3"
                else "不可用（UDP/443 被阻断，Pixiv 主站会连接重置）"
            )
            .append('\n')

        dns = launch(dnsBin,
            "-listen", "127.0.0.1:$dnsPort",
            "-doh", "https://cloudflare-dns.com/dns-query",
            "-hijack", "i.pximg.net",
            "-hijack-lan-ip", "127.0.0.1",
            "-lan-cidr", "0.0.0.0/0",
            "-h3-hint", "inject",
            "-cache-size", "4096"
        ).also {
            sb.append("DNS  : ").append(
                when {
                    !it.isAlive -> "启动失败"
                    quicAvailable == true -> "127.0.0.1:$dnsPort (DoH3)"
                    else -> "127.0.0.1:$dnsPort (进程在，但 QUIC 不通，解析会失败)"
                }
            ).append('\n')
        }

        web = launch(nginxBin,
            "-p", dir.absolutePath,
            "-c", File(dir, "nginx.conf").absolutePath,
            "-g", "daemon off;"
        )
        Thread.sleep(400)
        sb.append("反代 : ").append(if (web?.isAlive == true) "127.0.0.1:$proxyPort → i.pximg.net" else "启动失败")
        return sb.toString()
    }

    fun stop() {
        web?.let { runCatching { it.destroy() } }
        dns?.let { runCatching { it.destroy() } }
        web = null
        dns = null
    }

    private fun launch(bin: File, vararg args: String): Process {
        val pb = ProcessBuilder(listOf(bin.absolutePath) + args)
        pb.directory(dir)
        pb.redirectErrorStream(true)
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(logFile))
        return pb.start()
    }

    /**
     * 用 DNS 核心自带的 -probe 实打实发一次 HTTP/3 查询（UDP/443 → Cloudflare）。
     * 失败说明当前网络不允许 QUIC，此时给客户端注入 alpn=h3 只会让它先撞墙再回退，
     * 表现为连接被重置、图片加载失败，所以启动时据此决定是否开启 h3 标记。
     */
    private fun probeQuic(bin: File): Boolean = runCatching {
        val p = ProcessBuilder(bin.absolutePath, "-probe", "example.com", "-timeout", "4s")
            .redirectErrorStream(true)
            .start()
        val done = p.waitFor(8, TimeUnit.SECONDS)
        if (!done) p.destroyForcibly()
        done && p.exitValue() == 0
    }.getOrDefault(false)

    private fun portFree(p: Int) = runCatching {
        ServerSocket().use {
            it.reuseAddress = true
            it.bind(InetSocketAddress("127.0.0.1", p))
        }
        true
    }.getOrDefault(false)

    private fun freePort(from: Int): Int {
        for (p in from until from + 200) if (portFree(p)) return p
        return from
    }

    private fun copyAsset(name: String) {
        val out = File(dir, File(name).name)
        if (out.exists()) return
        runCatching {
            ctx.assets.open(name).use { i -> out.outputStream().use { i.copyTo(it) } }
        }
    }

    private fun writeNginxConf() {
        val upstream = listOf(
            "210.140.139.131", "210.140.139.132", "210.140.139.133", "210.140.139.134",
            "210.140.139.135", "210.140.139.136", "210.140.139.137", "210.140.139.138",
            "210.140.139.149", "210.140.139.150"
        ).joinToString("\n") { "        server $it:443;" }

        // nginx 上游直连 Pixiv 边缘 IP；SNI 固定 i.pximg.net，避免依赖本地 DNS 造成回环
        val conf = """
            worker_processes 1;
            error_log  ${dir.absolutePath}/error.log warn;
            pid        ${dir.absolutePath}/nginx.pid;
            events { worker_connections 1024; }
            http {
                include       ${dir.absolutePath}/mime.types;
                default_type  application/octet-stream;
                access_log    off;
                sendfile      on;
                keepalive_timeout 65;
                proxy_buffering off;
                proxy_max_temp_file_size 0;
                upstream i_pximg {
                    least_conn;
            $upstream
                    keepalive 16;
                }
                server {
                    listen 127.0.0.1:$proxyPort;
                    server_name i.pximg.net;
                    location / {
                        proxy_pass https://i_pximg;
                        proxy_http_version 1.1;
                        proxy_set_header Connection "";
                        proxy_set_header Host i.pximg.net;
                        proxy_set_header Referer "https://www.pixiv.net/";
                        proxy_set_header User-Agent ${'$'}http_user_agent;
                        proxy_ssl_server_name on;
                        # 关键：i.pximg.net 的 SNI 会被阻断，Pixiv-Nginx 同样用空 SNI
                        proxy_ssl_name "";
                        proxy_connect_timeout 8s;
                        proxy_read_timeout 30s;
                        proxy_next_upstream error timeout http_429 http_404 http_500 http_502 http_503 http_504;
                    }
                }
            }
        """.trimIndent()
        File(dir, "nginx.conf").writeText(conf)
    }
}
