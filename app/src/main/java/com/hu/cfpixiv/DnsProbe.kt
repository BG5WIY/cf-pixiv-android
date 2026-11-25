package com.hu.cfpixiv

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.random.Random

/** 直接向本地 Go DNS(127.0.0.1:5353) 发一次 A 查询，用于和系统解析结果对比 */
object DnsProbe {

    fun query(name: String, port: Int = 5353): List<String> {
        val id = Random.nextInt(0x10000)
        val out = ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xff)
        out.write(0x01); out.write(0x00)      // RD
        out.write(0x00); out.write(0x01)      // QDCOUNT=1
        repeat(6) { out.write(0) }
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray())
        }
        out.write(0)
        out.write(0x00); out.write(0x01)      // A
        out.write(0x00); out.write(0x01)      // IN
        val q = out.toByteArray()

        DatagramSocket().use { s ->
            s.soTimeout = 5000
            s.send(DatagramPacket(q, q.size, InetAddress.getByName("127.0.0.1"), port))
            val buf = ByteArray(4096)
            val rp = DatagramPacket(buf, buf.size)
            s.receive(rp)
            return parse(buf, rp.length)
        }
    }

    private fun parse(b: ByteArray, n: Int): List<String> {
        if (n < 12) return listOf("响应过短")
        val rcode = b[3].toInt() and 0x0f
        if (rcode != 0) return listOf("rcode=$rcode")
        val an = ((b[6].toInt() and 0xff) shl 8) or (b[7].toInt() and 0xff)
        var off = 12
        while (off < n && b[off].toInt() != 0) off += (b[off].toInt() and 0xff) + 1
        off += 5

        val res = mutableListOf<String>()
        var i = 0
        while (i < an && off < n) {
            off = skipName(b, off)
            if (off + 10 > n) break
            val type = ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)
            off += 8
            val rdlen = ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)
            off += 2
            if (type == 1 && rdlen == 4 && off + 4 <= n) {
                res.add("${b[off].toInt() and 0xff}.${b[off + 1].toInt() and 0xff}." +
                        "${b[off + 2].toInt() and 0xff}.${b[off + 3].toInt() and 0xff}")
            }
            off += rdlen
            i++
        }
        return if (res.isEmpty()) listOf("无 A 记录") else res
    }

    private fun skipName(b: ByteArray, start: Int): Int {
        var o = start
        while (o < b.size) {
            val len = b[o].toInt() and 0xff
            if (len == 0) return o + 1
            if (len and 0xc0 == 0xc0) return o + 2
            o += len + 1
        }
        return o
    }
}
