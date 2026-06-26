package app.ykdf.nfc

import android.nfc.tech.IsoDep

/** A parsed response APDU: the response data plus the two status bytes. */
class ResponseApdu(val data: ByteArray, val sw1: Int, val sw2: Int) {
    val isSuccess: Boolean get() = sw1 == 0x90 && sw2 == 0x00
    val status: Int get() = (sw1 shl 8) or sw2
}

/**
 * Minimal ISO 7816-4 APDU helpers over [IsoDep], with `61xx` GET RESPONSE
 * chaining. Deliberately tiny and dependency-free: this is the entire
 * YubiKey-facing wire surface, so it stays auditable.
 */
object Apdu {
    private const val GET_RESPONSE_INS = 0xC0

    /**
     * Build a short-form command APDU.
     *
     * `le = null` omits the Le byte (case 1/3 commands such as VERIFY PIN);
     * a non-null `le` appends it (case 2/4). `0x00` means "up to 256 bytes".
     */
    fun command(
        cla: Int,
        ins: Int,
        p1: Int,
        p2: Int,
        data: ByteArray = ByteArray(0),
        le: Int? = 0x00,
    ): ByteArray {
        require(data.size <= 255) { "short APDU data must be <= 255 bytes" }
        val out = ArrayList<Byte>(6 + data.size)
        out.add(cla.toByte())
        out.add(ins.toByte())
        out.add(p1.toByte())
        out.add(p2.toByte())
        if (data.isNotEmpty()) {
            out.add(data.size.toByte())
            for (b in data) out.add(b)
        }
        if (le != null) out.add(le.toByte())
        return out.toByteArray()
    }

    /**
     * Transceive [apdu], following any `61xx` status with GET RESPONSE and
     * accumulating the data, so callers see one logical response.
     */
    fun send(isoDep: IsoDep, apdu: ByteArray): ResponseApdu {
        var resp = isoDep.transceive(apdu)
        val acc = ArrayList<Byte>()
        while (true) {
            require(resp.size >= 2) { "truncated response APDU" }
            val sw1 = resp[resp.size - 2].toInt() and 0xFF
            val sw2 = resp[resp.size - 1].toInt() and 0xFF
            for (i in 0 until resp.size - 2) acc.add(resp[i])
            if (sw1 == 0x61) {
                resp = isoDep.transceive(command(0x00, GET_RESPONSE_INS, 0x00, 0x00, le = sw2))
            } else {
                return ResponseApdu(acc.toByteArray(), sw1, sw2)
            }
        }
    }
}

/**
 * Single-level BER-TLV reader for the few single-byte tags this app parses
 * (`0x53`, `0x70`, `0x71`, `0x7C`, `0x82`, `0x85`). Handles short and long
 * (`0x81`/`0x82`) length forms. Callers drill into nested structures by calling
 * [findValue] again on a returned value.
 */
object BerTlv {
    /** Return the value of the first TLV with single-byte [tag], or null. */
    fun findValue(bytes: ByteArray, tag: Int): ByteArray? {
        var i = 0
        while (i + 1 < bytes.size) {
            val t = bytes[i].toInt() and 0xFF
            i++
            var len = bytes[i].toInt() and 0xFF
            i++
            if (len and 0x80 != 0) {
                val n = len and 0x7F
                if (n == 0 || i + n > bytes.size) return null
                len = 0
                repeat(n) {
                    len = (len shl 8) or (bytes[i].toInt() and 0xFF)
                    i++
                }
            }
            if (i + len > bytes.size) return null
            if (t == tag) return bytes.copyOfRange(i, i + len)
            i += len
        }
        return null
    }
}
