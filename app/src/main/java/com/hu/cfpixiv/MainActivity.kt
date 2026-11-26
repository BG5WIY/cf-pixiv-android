package com.hu.cfpixiv

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import java.net.InetAddress

class MainActivity : Activity() {

    private lateinit var core: Core
    private lateinit var status: TextView
    private lateinit var vpnBtn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        core = Core(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
        }
        status = TextView(this).apply {
            text = "未启动\n\n用法：启动 → VPN → 在系统浏览器访问 i.pximg.net"
            textSize = 13f
            setPadding(28, 32, 28, 12)
            setTextColor(Color.rgb(30, 30, 30))
        }

        fun row(): LinearLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(14, 0, 14, 6)
        }
        fun cell(label: String, onClick: () -> Unit): Button = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }

        val bar1 = row().apply {
            addView(cell("启动") {
                status.text = "启动中…"
                Thread { val s = core.start(); runOnUiThread { status.text = s } }.start()
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cell("停止") {
                core.stop()
                status.text = "已停止"
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }

        vpnBtn = cell(if (DnsVpnService.running) "VPN 开" else "VPN 关") {}
        vpnBtn.setOnClickListener { onVpnClick() }

        val bar2 = row().apply {
            addView(vpnBtn, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cell("导出CA") { exportCa() },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cell("日志") { showLogs() },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cell("自检") { selfCheck() },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }

        val input = EditText(this).apply {
            hint = "输入域名检测"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine()
        }
        val bar3 = row().apply {
            addView(input, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(cell("检测") { probeHost(input.text.toString().trim()) })
        }

        val hint = TextView(this).apply {
            text = "CA 安装：设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书\n" +
                    "（Android 7+ 用户 CA 需应用主动信任，系统浏览器默认支持）"
            textSize = 12f
            setPadding(28, 24, 28, 0)
            setTextColor(Color.DKGRAY)
        }

        root.addView(status)
        root.addView(bar1)
        root.addView(bar2)
        root.addView(bar3)
        root.addView(hint)
        setContentView(root)
    }

    private fun onVpnClick() {
        if (DnsVpnService.running) {
            stopService(Intent(this, DnsVpnService::class.java))
            vpnBtn.text = "VPN 关"
            status.text = "VPN 已关闭"
            return
        }
        status.text = "检查 DNS…"
        Thread {
            if (!core.isRunning()) core.start()
            val ok = runCatching { DnsProbe.query("example.com") }.isSuccess
            runOnUiThread {
                if (ok) {
                    vpnBtn.text = "VPN 开"
                    toggleVpn()
                } else {
                    status.text = "本地 DNS 不可用（QUIC 不通？），先点「启动」看日志"
                }
            }
        }.start()
    }

    /** 把内置的 CA 证书通过系统文件选择器导出到用户可访问的位置 */
    private fun exportCa() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/x-x509-ca-cert"
            putExtra(Intent.EXTRA_TITLE, "cf-pixiv-ca.crt")
        }
        runCatching { startActivityForResult(intent, 2001) }
            .onFailure { status.text = "无法打开保存对话框：${it.message}" }
    }

    private fun selfCheck() {
        status.text = "自检中…"
        Thread {
            val sb = StringBuilder()
            for (host in listOf("www.pixiv.net", "i.pximg.net")) {
                val r = runCatching { DnsProbe.query(host) }.getOrElse { listOf("错误: ${it.message}") }
                sb.append(host).append(" → ").append(r.joinToString()).append('\n')
            }
            sb.append("cloudflare-quic.com HTTPS → ").append(
                runCatching { DnsProbe.httpsAlpn("cloudflare-quic.com") }.getOrElse { "错误: ${it.message}" }
            ).append('\n')
            sb.append("系统: ").append(
                runCatching { InetAddress.getAllByName("www.pixiv.net").joinToString { it.hostAddress ?: "?" } }
                    .getOrElse { "错误: ${it.message}" }
            )
            runOnUiThread { status.text = sb.toString() }
        }.start()
    }

    private fun probeHost(host: String) {
        if (host.isEmpty()) return
        status.text = "检测 $host …"
        Thread {
            val a = runCatching { DnsProbe.query(host) }.getOrElse { listOf("错误: ${it.message}") }
            val h = runCatching { DnsProbe.httpsAlpn(host) }.getOrElse { "错误: ${it.message}" }
            val sys = runCatching {
                InetAddress.getAllByName(host).joinToString { it.hostAddress ?: "?" }
            }.getOrElse { "错误: ${it.message}" }
            val sysHttps = systemHttpsAlpn(host)
            runOnUiThread {
                status.text = buildString {
                    append(host).append('\n')
                    append("DoH3 A    : ").append(a.joinToString()).append('\n')
                    append("DoH3 HTTPS: ").append(h).append('\n')
                    append("系统解析  : ").append(sys).append('\n')
                    append("系统 HTTPS: ").append(sysHttps)
                }
            }
        }.start()
    }

    /** 用系统当前 DNS 服务器查 HTTPS 记录，用来和 DoH3 结果对照（VPN 开了才会一致） */
    private fun systemHttpsAlpn(host: String): String = try {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val net = cm.activeNetwork
        val lp = net?.let { cm.getLinkProperties(it) }
        val dns = lp?.dnsServers?.firstOrNull { it is java.net.Inet4Address }
            ?: lp?.dnsServers?.firstOrNull()
        if (dns == null) "无 DNS 服务器"
        else DnsProbe.httpsAlpn(host, dns.hostAddress ?: "127.0.0.1", 53)
    } catch (e: Exception) {
        "错误: ${e.message}"
    }

    private fun showLogs() {
        Thread {
            val content = readLogText()
            runOnUiThread {
                val tv = TextView(this).apply {
                    text = content
                    textSize = 11f
                    setTextIsSelectable(true)
                    setPadding(24, 16, 24, 16)
                    typeface = android.graphics.Typeface.MONOSPACE
                }
                val scroll = android.widget.ScrollView(this).apply { addView(tv) }
                AlertDialog.Builder(this)
                    .setTitle("运行日志")
                    .setView(scroll)
                    .setPositiveButton("关闭", null)
                    .setNeutralButton("分享") { _, _ ->
                        startActivity(
                            Intent.createChooser(
                                Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, content)
                                }, "分享日志"
                            )
                        )
                    }
                    .show()
            }
        }.start()
    }

    private fun readLogText(): String {
        val base = getExternalFilesDir("core") ?: java.io.File(filesDir, "core")
        val sb = StringBuilder()
        for (name in listOf("vpn.log", "core.log", "error.log")) {
            val f = java.io.File(base, name)
            sb.append("===== ").append(name).append(" =====\n")
            if (f.exists()) {
                sb.append(f.readLines().takeLast(150).joinToString("\n"))
            } else {
                sb.append("(无)")
            }
            sb.append("\n\n")
        }
        return sb.toString()
    }

    private fun toggleVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 1001)
        else startService(Intent(this, DnsVpnService::class.java))
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            1001 -> {
                if (resultCode == RESULT_OK) startService(Intent(this, DnsVpnService::class.java))
                else {
                    vpnBtn.text = "VPN 关"
                    status.text = "VPN 授权被拒绝"
                }
            }
            2001 -> {
                if (resultCode == RESULT_OK && data?.data != null) {
                    val ok = runCatching {
                        contentResolver.openOutputStream(data.data!!)?.use { out ->
                            assets.open("nginx/ca.crt").use { it.copyTo(out) }
                        }
                    }.isSuccess
                    status.text = if (ok)
                        "CA 已保存。安装：设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书"
                    else "保存失败"
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
    }
}
