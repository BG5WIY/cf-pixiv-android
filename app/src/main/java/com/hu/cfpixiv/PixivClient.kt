package com.hu.cfpixiv

import android.net.Uri
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import java.net.HttpURLConnection
import java.net.URL

/**
 * 把网页里所有 i.pximg.net 请求转到本地 nginx 反代（127.0.0.1:proxyPort），
 * 这是 443 不可用时的兜底路径：不改网页源码，只在 WebView 出口改写。
 */
class PixivClient(
    private val core: Core,
    private val onError: (String) -> Unit = {}
) : WebViewClient() {

    override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
        if (request.isForMainFrame) {
            onError("主站加载失败：${error.description}（Pixiv 需要 h3，QUIC 不通时会被重置）")
        }
    }

    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
        val u = request.url
        if (!"i.pximg.net".equals(u.host, ignoreCase = true)) return null
        return runCatching { fetch(u) }.getOrNull()
    }

    private fun fetch(u: Uri): WebResourceResponse {
        val path = (u.encodedPath ?: "/") + (u.encodedQuery?.let { "?$it" } ?: "")
        val conn = URL("http://127.0.0.1:${core.proxyPort}$path").openConnection() as HttpURLConnection
        conn.connectTimeout = 8_000
        conn.readTimeout = 30_000
        conn.instanceFollowRedirects = false
        val code = conn.responseCode
        val headers = HashMap<String, String>()
        conn.headerFields.forEach { (k, v) -> if (k != null && v != null) headers[k] = v.joinToString(", ") }
        val body = if (code >= 400) conn.errorStream else conn.inputStream
            ?: return WebResourceResponse("application/octet-stream", null, code, "", headers, null)
        val mime = conn.contentType?.substringBefore(';') ?: "application/octet-stream"
        return WebResourceResponse(mime, null, code, "", headers, body)
    }
}
