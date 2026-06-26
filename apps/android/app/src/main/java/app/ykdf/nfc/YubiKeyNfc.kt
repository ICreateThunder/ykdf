package app.ykdf.nfc

import android.nfc.tech.IsoDep
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

/** Raised when the YubiKey NFC exchange fails. */
class YubiKeyNfcException(message: String) : Exception(message)

/**
 * Minimal, dependency-free YubiKey NFC handler (custom APDU layer, no yubikit).
 *
 * It reproduces exactly the input key material the desktop `ykdf-yubikey` crate
 * produces, so on-device derivation matches the CLI byte-for-byte:
 * - standard: PIV self-ECDH on slot 9d (Key Management), 32 bytes
 * - layered:  ECDH(32) || HMAC-SHA1 challenge-response on OTP slot 2 (20) = 52
 *
 * Self-ECDH means the slot-9d private key is multiplied by its own public point
 * (read from the slot certificate), which is deterministic per device.
 */
object YubiKeyNfc {
    // Standard PIV applet AID.
    private val AID_PIV =
        byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00)

    // YubiKey OTP / challenge-response applet AID.
    private val AID_OTP =
        byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x20, 0x01)

    // Frozen v1 HMAC challenge. Must equal CHALLENGE in ykdf-yubikey/src/hmac.rs.
    private val CHALLENGE = "ykdf-v1".toByteArray(Charsets.US_ASCII)

    private const val INS_VERIFY = 0x20
    private const val INS_GET_DATA = 0xCB
    private const val INS_GENERAL_AUTHENTICATE = 0x87
    private const val INS_SELECT = 0xA4
    private const val INS_OTP_PUT = 0x01

    private const val ALG_ECC_P256 = 0x11
    private const val SLOT_9D = 0x9D
    private const val OTP_SLOT2 = 0x38 // CHALLENGE_HMAC_2 in Yubico's slot map

    private const val ECDH_SECRET_LEN = 32
    private const val HMAC_RESPONSE_LEN = 20

    /**
     * Read the YubiKey over [isoDep] and return the IKM for `ykdf-core`.
     *
     * Must run off the UI thread: ECDH and HMAC may block on user presence.
     */
    fun deriveIkm(isoDep: IsoDep, pin: ByteArray, layered: Boolean): ByteArray {
        isoDep.connect()
        isoDep.timeout = 15_000

        selectApplet(isoDep, AID_PIV)
        val point = readSlot9dPublicPoint(isoDep)
        verifyPin(isoDep, pin)
        val ecdh = ecdh(isoDep, point)
        if (!layered) return ecdh

        selectApplet(isoDep, AID_OTP)
        val hmac = hmacSlot2(isoDep)
        return ecdh + hmac
    }

    private fun selectApplet(isoDep: IsoDep, aid: ByteArray) {
        val r = Apdu.send(isoDep, Apdu.command(0x00, INS_SELECT, 0x04, 0x00, aid))
        if (!r.isSuccess) throw YubiKeyNfcException("SELECT failed: ${hex(r.status)}")
    }

    private fun verifyPin(isoDep: IsoDep, pin: ByteArray) {
        require(pin.size in 1..8) { "PIN must be 1..8 bytes" }
        // PIV VERIFY expects the PIN right-padded to 8 bytes with 0xFF.
        val padded = ByteArray(8) { 0xFF.toByte() }
        System.arraycopy(pin, 0, padded, 0, pin.size)
        val r = Apdu.send(isoDep, Apdu.command(0x00, INS_VERIFY, 0x00, 0x80, padded, le = null))
        padded.fill(0)
        if (!r.isSuccess) throw YubiKeyNfcException("VERIFY PIN failed: ${hex(r.status)}")
    }

    private fun readSlot9dPublicPoint(isoDep: IsoDep): ByteArray {
        // GET DATA for the Key Management certificate object (tag 5F C1 0B).
        val tagList = byteArrayOf(0x5C, 0x03, 0x5F, 0xC1.toByte(), 0x0B)
        val r = Apdu.send(isoDep, Apdu.command(0x00, INS_GET_DATA, 0x3F, 0xFF, tagList))
        if (!r.isSuccess) throw YubiKeyNfcException("GET DATA (cert) failed: ${hex(r.status)}")

        val obj = BerTlv.findValue(r.data, 0x53)
            ?: throw YubiKeyNfcException("certificate object (0x53) not found")
        val compression = BerTlv.findValue(obj, 0x71)
        if (compression != null && compression.isNotEmpty() && compression[0].toInt() != 0) {
            throw YubiKeyNfcException("compressed slot-9d certificate is not supported")
        }
        val certDer = BerTlv.findValue(obj, 0x70)
            ?: throw YubiKeyNfcException("certificate (0x70) not found")

        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        val ec = cert.publicKey as? ECPublicKey
            ?: throw YubiKeyNfcException("slot 9d does not hold an EC key")
        return uncompressedPoint(ec)
    }

    private fun ecdh(isoDep: IsoDep, point: ByteArray): ByteArray {
        // GENERAL AUTHENTICATE: 7C { 82 00 (response placeholder), 85 <peer point> }
        val inner = byteArrayOf(0x82.toByte(), 0x00, 0x85.toByte(), point.size.toByte()) + point
        val template = byteArrayOf(0x7C, inner.size.toByte()) + inner
        val r = Apdu.send(
            isoDep,
            Apdu.command(0x00, INS_GENERAL_AUTHENTICATE, ALG_ECC_P256, SLOT_9D, template),
        )
        if (!r.isSuccess) throw YubiKeyNfcException("GENERAL AUTHENTICATE failed: ${hex(r.status)}")

        val resp = BerTlv.findValue(r.data, 0x7C)
            ?: throw YubiKeyNfcException("no dynamic auth template (0x7C) in response")
        val secret = BerTlv.findValue(resp, 0x82)
            ?: throw YubiKeyNfcException("no shared secret (0x82) in response")
        if (secret.size != ECDH_SECRET_LEN) {
            throw YubiKeyNfcException("ECDH secret ${secret.size} != $ECDH_SECRET_LEN")
        }
        return secret
    }

    private fun hmacSlot2(isoDep: IsoDep): ByteArray {
        val r = Apdu.send(isoDep, Apdu.command(0x00, INS_OTP_PUT, OTP_SLOT2, 0x00, CHALLENGE))
        if (!r.isSuccess) throw YubiKeyNfcException("HMAC challenge failed: ${hex(r.status)}")
        if (r.data.size != HMAC_RESPONSE_LEN) {
            throw YubiKeyNfcException("HMAC response ${r.data.size} != $HMAC_RESPONSE_LEN")
        }
        return r.data
    }

    /** Encode an EC public key as uncompressed SEC1 (0x04 || X(32) || Y(32)). */
    private fun uncompressedPoint(ec: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + fixedWidth(ec.w.affineX, 32) + fixedWidth(ec.w.affineY, 32)

    /** Left-pad/trim a non-negative BigInteger to exactly [len] big-endian bytes. */
    private fun fixedWidth(v: BigInteger, len: Int): ByteArray {
        val raw = v.toByteArray() // may carry a leading 0x00 sign byte, or be short
        val out = ByteArray(len)
        when {
            raw.size == len -> System.arraycopy(raw, 0, out, 0, len)
            raw.size < len -> System.arraycopy(raw, 0, out, len - raw.size, raw.size)
            else -> System.arraycopy(raw, raw.size - len, out, 0, len) // drop sign byte(s)
        }
        return out
    }

    private fun hex(v: Int): String = "0x%04X".format(v)
}
