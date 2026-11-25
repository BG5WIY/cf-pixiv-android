package com.hu.cfpixiv

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var core: Core
    private lateinit var status: TextView
    private lateinit var web: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        core = Core(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
        }
        status = TextView(this).apply {
            text = "未启动"
            textSize = 13f
            setPadding(28, 28, 28, 12)
            setTextColor(Color.rgb(30, 30, 30))
        }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(20, 0, 20, 12)
        }
        fun btn(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
            bar.addView(this, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        btn("启动") { status.text = "启动中…"; Thread { val s = core.start(); runOnUiThread { status.text = s } }.start() }
        btn("停止") { core.stop(); status.text = "已停止" }
        btn("VPN") {
            if (core.isRunning()) {
                toggleVpn()
            } else {
                // VPN 依赖本地 DNS 进程，没启动就先拉起来
                status.text = "启动中…"
                Thread {
                    val msg = core.start()
                    runOnUiThread {
                        status.text = msg
                        toggleVpn()
                    }
                }.start()
            }
        }
        btn("Pixiv") { web.loadUrl("https://www.pixiv.net/") }

        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.databaseEnabled = true
            settings.loadWithOverviewMode = true
            settings.useWideViewPort = true
            settings.userAgentString =
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
            webViewClient = PixivClient(core) { msg ->
                status.post { status.text = msg }
            }
        }

        root.addView(status)
        root.addView(bar)
        root.addView(web, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
    }

    private fun toggleVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 1001)
        else startService(Intent(this, DnsVpnService::class.java))
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == RESULT_OK) startService(Intent(this, DnsVpnService::class.java))
    }

    override fun onDestroy() {
        web.destroy()
        super.onDestroy()
    }
}
