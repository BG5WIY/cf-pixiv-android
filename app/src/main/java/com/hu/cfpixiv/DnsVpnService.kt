package com.hu.cfpixiv

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * 只接管 DNS 的 VPN：把系统 DNS 指向 10.111.222.1，
 * TUN 里收到的 UDP/53 转给本地 Go DNS（127.0.0.1:5353），
 * 这样系统解析走 Cloudflare DoH3，i.pximg.net 被劫持到 127.0.0.1。
 */
class DnsVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        foreground()
        val b = Builder()
            .setSession("CF Pixiv DNS")
            .addAddress("10.111.222.1", 32)
            .addDnsServer("10.111.222.1")
            .addRoute("10.111.222.1", 32)
            .setBlocking(true)
            .setMtu(1500)
        runCatching { b.addDisallowedApplication(packageName) }
        tun = b.establish() ?: return START_NOT_STICKY
        running = true
        worker = Thread(::loop, "dns-tun").apply { start() }
        return START_STICKY
    }

    private fun foreground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel("dns", "DNS", NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = Notification.Builder(this, "dns")
            .setContentTitle("CF Pixiv")
            .setContentText("DNS 走 Cloudflare DoH3")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, n)
        }
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        val local = runCatching {
            DatagramSocket().apply {
                soTimeout = 4000
                connect(InetAddress.getByName("127.0.0.1"), 5353)
            }
        }.getOrNull() ?: return

        while (running && !Thread.interrupted()) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                break
            }
            if (n <= 0 || (buf[0].toInt() shr 4) != 4) continue
            val ihl = (buf[0].toInt() and 0x0f) * 4
            if (n < ihl + 8 || buf[9].toInt() != 17) continue
            val dstPort = ((buf[ihl + 2].toInt() and 0xff) shl 8) or (buf[ihl + 3].toInt() and 0xff)
            if (dstPort != 53) continue

            val q = buf.copyOfRange(ihl + 8, n)
            val resp = try {
                local.send(DatagramPacket(q, q.size))
                val rb = ByteArray(4096)
                val rp = DatagramPacket(rb, rb.size)
                local.receive(rp)
                rb.copyOf(rp.length)
            } catch (e: Exception) {
                null
            } ?: continue
            writeBack(buf, n, ihl, resp, output)
        }
        runCatching { local.close() }
    }

    private fun writeBack(orig: ByteArray, n: Int, ihl: Int, dns: ByteArray, out: FileOutputStream) {
        val udpLen = 8 + dns.size
        val total = ihl + udpLen
        val p = ByteArray(total)
        System.arraycopy(orig, 0, p, 0, ihl)
        for (i in 0 until 4) {
            val t = p[12 + i]; p[12 + i] = p[16 + i]; p[16 + i] = t
        }
        p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[8] = 64; p[9] = 17; p[10] = 0; p[11] = 0
        var sum = 0
        for (i in 0 until ihl step 2) {
            sum += ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
        }
        while (sum shr 16 != 0) sum = (sum and 0xffff) + (sum shr 16)
        val ck = sum.inv() and 0xffff
        p[10] = (ck shr 8).toByte(); p[11] = ck.toByte()
        p[ihl] = orig[ihl + 2]; p[ihl + 1] = orig[ihl + 3]
        p[ihl + 2] = orig[ihl]; p[ihl + 3] = orig[ihl + 1]
        p[ihl + 4] = (udpLen shr 8).toByte(); p[ihl + 5] = udpLen.toByte()
        p[ihl + 6] = 0; p[ihl + 7] = 0
        System.arraycopy(dns, 0, p, ihl + 8, dns.size)
        out.write(p)
    }

    override fun onDestroy() {
        running = false
        worker?.interrupt()
        runCatching { tun?.close() }
        tun = null
        super.onDestroy()
    }
}
