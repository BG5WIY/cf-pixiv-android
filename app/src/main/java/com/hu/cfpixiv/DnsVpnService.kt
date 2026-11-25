package com.hu.cfpixiv

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * 只接管 piXimg 的 VPN：
 *  - 路由仅 10.111.222.0/24，其他流量完全不过 VPN，不影响别的 App
 *  - DNS 由 Go 进程劫持 i.pximg.net -> 10.111.222.3
 *  - TUN 里 UDP/53 转给本地 Go DNS；TCP/443 转给本地 nginx(127.0.0.1:8443)
 *    这样客户端看到的是 443，实际由用户态转发，无需 root。
 */
class DnsVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var running = false

    private val conns = ConcurrentHashMap<Long, TcpConn>()

    companion object {
        const val VPN_ADDR = "10.111.222.3"
        private const val DNS_ADDR = "10.111.222.1"
        private const val CLIENT_ADDR = "10.111.222.2"
        private const val LOCAL_PROXY_PORT = 8444

        private const val FIN = 0x01
        private const val SYN = 0x02
        private const val RST = 0x04
        private const val PSH = 0x08
        private const val ACK = 0x10

        private fun ipToInt(s: String): Int {
            val p = s.split('.').map { it.toInt() }
            return (p[0] shl 24) or (p[1] shl 16) or (p[2] shl 8) or p[3]
        }
    }

    private val vpnIp = ipToInt(VPN_ADDR)
    private val clientIp = ipToInt(CLIENT_ADDR)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        foreground()
        val b = Builder()
            .setSession("CF Pixiv DNS")
            .addAddress(CLIENT_ADDR, 24)
            .addDnsServer(DNS_ADDR)
            .addRoute("10.111.222.0", 24)
            .setBlocking(true)
            .setMtu(1500)
        tun = b.establish() ?: run {
            log("establish() 返回 null")
            return START_NOT_STICKY
        }
        running = true
        log("tun up: addr=$CLIENT_ADDR/24 dns=$DNS_ADDR proxy=$VPN_ADDR:443 -> 127.0.0.1:$LOCAL_PROXY_PORT")
        worker = Thread(::loop, "tun").apply { start() }
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
            .setContentText("i.pximg.net:443 → 本地反代")
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

    private fun log(msg: String) {
        runCatching {
            val base = getExternalFilesDir("core") ?: File(filesDir, "core")
            base.mkdirs()
            val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
            File(base, "vpn.log").appendText("$ts $msg\n")
        }
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)

        val dns = runCatching {
            DatagramSocket().apply {
                soTimeout = 4000
                connect(InetAddress.getByName("127.0.0.1"), 5353)
            }
        }.getOrNull()

        var dnsOk = 0
        var dnsFail = 0
        log("loop start")
        while (running && !Thread.interrupted()) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                log("tun read 结束: $e")
                break
            }
            if (n <= 0 || (buf[0].toInt() shr 4) != 4) continue
            val ihl = (buf[0].toInt() and 0x0f) * 4
            if (n < ihl + 8) continue

            when (buf[9].toInt() and 0xff) {
                17 -> { // UDP: 只处理 DNS
                    val dstPort = u16(buf, ihl + 2)
                    if (dstPort != 53 || dns == null) continue
                    val q = buf.copyOfRange(ihl + 8, n)
                    val resp = try {
                        dns.send(DatagramPacket(q, q.size))
                        val rb = ByteArray(4096)
                        val rp = DatagramPacket(rb, rb.size)
                        dns.receive(rp)
                        rb.copyOf(rp.length)
                    } catch (e: Exception) {
                        null
                    }
                    if (resp == null) {
                        dnsFail++
                        if (dnsFail == 1 || dnsFail % 10 == 0) log("DNS 转发失败 fail=$dnsFail")
                        continue
                    }
                    dnsOk++
                    if (dnsOk == 1 || dnsOk % 50 == 0) log("DNS ok=$dnsOk fail=$dnsFail")
                    writeBack(buf, n, ihl, resp, output, 17)
                }
                6 -> handleTcp(buf, n, ihl, output)
            }
        }
        runCatching { dns?.close() }
    }

    // ---------------- TCP ----------------

    private inner class TcpConn(
        val key: Long,
        val clientPort: Int,
        val socket: Socket
    ) {
        var expectSeq = 0L          // 期待客户端下一个 seq
        var sendSeq = Random.nextLong(1, 1L shl 31)  // 我们发出的下一个 seq
        @Volatile var closed = false
    }

    private fun connKey(clientPort: Int) = (clientPort.toLong() and 0xffff)

    private fun handleTcp(pkt: ByteArray, n: Int, ihl: Int, out: FileOutputStream) {
        if (n < ihl + 20) return
        val dstIp = s32(pkt, 16)
        val dstPort = u16(pkt, ihl + 2)
        if (dstIp != vpnIp.toLong() || dstPort != 443) return

        val srcPort = u16(pkt, ihl)
        val seq = s32(pkt, ihl + 4)
        val flags = pkt[ihl + 13].toInt() and 0xff
        val doff = ((pkt[ihl + 12].toInt() and 0xf0) shr 4) * 4
        if (doff < 20 || ihl + doff > n) return
        val payload = pkt.copyOfRange(ihl + doff, n)
        val key = connKey(srcPort)

        if (flags and SYN != 0) {
            val conn = conns.remove(key)
            conn?.let { runCatching { it.socket.close() } }
            val sock = try {
                Socket("127.0.0.1", LOCAL_PROXY_PORT).apply { tcpNoDelay = true; soTimeout = 0 }
            } catch (e: Exception) {
                log("连接本地反代失败: $e")
                sendTcp(srcPort, seq + 1, 0L, RST or ACK, ByteArray(0), out)
                return
            }
            val c = TcpConn(key, srcPort, sock)
            c.expectSeq = seq + 1
            conns[key] = c
            sendTcp(srcPort, c.sendSeq, c.expectSeq, SYN or ACK, ByteArray(0), out)
            c.sendSeq = c.sendSeq + 1
            pump(c, out)
            return
        }

        val c = conns[key] ?: run {
            sendTcp(srcPort, seq + 1, 0L, RST or ACK, ByteArray(0), out)
            return
        }

        if (flags and RST != 0) {
            closeConn(c)
            return
        }
        if (flags and FIN != 0) {
            runCatching { c.socket.shutdownOutput() }
            sendTcp(srcPort, c.sendSeq, c.expectSeq + 1, FIN or ACK, ByteArray(0), out)
            c.sendSeq += 1
            closeConn(c)
            return
        }
        if (payload.isNotEmpty()) {
            try {
                c.socket.getOutputStream().write(payload)
                c.socket.getOutputStream().flush()
            } catch (e: Exception) {
                sendTcp(srcPort, c.sendSeq, c.expectSeq, RST or ACK, ByteArray(0), out)
                closeConn(c)
                return
            }
            c.expectSeq = seq + payload.size
            sendTcp(srcPort, c.sendSeq, c.expectSeq, ACK, ByteArray(0), out)
        }
    }

    private fun pump(c: TcpConn, out: FileOutputStream) {
        thread(isDaemon = true, name = "tcp-${c.clientPort}") {
            val ins = c.socket.getInputStream()
            val buf = ByteArray(16384)
            try {
                while (!c.closed && running) {
                    val len = ins.read(buf)
                    if (len < 0) break
                    val data = buf.copyOf(len)
                    sendTcp(c.clientPort, c.sendSeq, c.expectSeq, PSH or ACK, data, out)
                    c.sendSeq += len
                }
            } catch (_: Exception) {
            } finally {
                if (!c.closed) {
                    runCatching { sendTcp(c.clientPort, c.sendSeq, c.expectSeq, FIN or ACK, ByteArray(0), out) }
                }
                closeConn(c)
            }
        }
    }

    private fun closeConn(c: TcpConn) {
        if (c.closed) return
        c.closed = true
        conns.remove(c.key)
        runCatching { c.socket.close() }
    }

    // ---------------- 包构造 ----------------

    private fun sendTcp(dstPort: Int, seq: Long, ack: Long, flags: Int, payload: ByteArray, out: FileOutputStream) {
        val tcpLen = 20 + payload.size
        val total = 20 + tcpLen
        val p = ByteArray(total)
        p[0] = 0x45.toByte()
        p[2] = ((total shr 8) and 0xff).toByte()
        p[3] = (total and 0xff).toByte()
        p[8] = 64.toByte()
        p[9] = 6.toByte()
        w32(p, 12, vpnIp)
        w32(p, 16, clientIp)

        val t = 20
        w16(p, t, 443)
        w16(p, t + 2, dstPort)
        w32(p, t + 4, seq)
        w32(p, t + 8, ack)
        p[t + 12] = (5 shl 4).toByte()
        p[t + 13] = flags.toByte()
        w16(p, t + 14, 65535)
        System.arraycopy(payload, 0, p, t + 20, payload.size)

        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(p, i)
        while (sum shr 16 != 0) sum = (sum and 0xffff) + (sum shr 16)
        w16(p, 10, sum.inv() and 0xffff)

        val tcpSum = pseudoSum(p, t, tcpLen) + tcpChecksum(p, t, tcpLen)
        var s = tcpSum
        while (s shr 16 != 0) s = (s and 0xffff) + (s shr 16)
        w16(p, t + 16, s.inv() and 0xffff)

        synchronized(out) { out.write(p) }
    }

    private fun pseudoSum(p: ByteArray, tcpOff: Int, tcpLen: Int): Int {
        var s = 0
        s += u16(p, 12); s += u16(p, 14)
        s += u16(p, 16); s += u16(p, 18)
        s += 6
        s += tcpLen
        return s
    }

    private fun tcpChecksum(p: ByteArray, off: Int, len: Int): Int {
        var s = 0
        var i = off
        val end = off + len
        while (i < end) {
            s += u16(p, i)
            i += 2
        }
        return s
    }

    private fun writeBack(orig: ByteArray, n: Int, ihl: Int, dns: ByteArray, out: FileOutputStream, proto: Int) {
        val udpLen = 8 + dns.size
        val total = ihl + udpLen
        val p = ByteArray(total)
        System.arraycopy(orig, 0, p, 0, ihl)
        for (i in 0 until 4) {
            val t = p[12 + i]; p[12 + i] = p[16 + i]; p[16 + i] = t
        }
        p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[8] = 64.toByte(); p[9] = proto.toByte(); p[10] = 0; p[11] = 0
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

    private fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    private fun w16(b: ByteArray, o: Int, v: Int) {
        b[o] = ((v shr 8) and 0xff).toByte()
        b[o + 1] = (v and 0xff).toByte()
    }

    private fun s32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) shl 24) or ((b[o + 1].toLong() and 0xff) shl 16) or
            ((b[o + 2].toLong() and 0xff) shl 8) or (b[o + 3].toLong() and 0xff)

    private fun w32(b: ByteArray, o: Int, v: Long) {
        b[o] = ((v shr 24) and 0xff).toByte()
        b[o + 1] = ((v shr 16) and 0xff).toByte()
        b[o + 2] = ((v shr 8) and 0xff).toByte()
        b[o + 3] = (v and 0xff).toByte()
    }

    private fun w32(b: ByteArray, o: Int, v: Int) = w32(b, o, v.toLong() and 0xffffffffL)

    override fun onDestroy() {
        running = false
        worker?.interrupt()
        conns.values.forEach { runCatching { it.socket.close() } }
        conns.clear()
        runCatching { tun?.close() }
        tun = null
        super.onDestroy()
    }
}
