package app.ykdf

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Spike UI: prove the full chain Compose -> JNI -> ykdf-core -> bytes.
 *
 * For now the input key material is typed as hex (the same 00..1f vector the
 * golden tests pin). The NFC tap that will supply this material from a YubiKey
 * is stubbed below ([deriveFromNfc]); wiring it is the remaining hardware step.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DeriveScreen()
                }
            }
        }
    }
}

@Composable
private fun DeriveScreen() {
    var ikmHex by remember {
        mutableStateOf("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    }
    var profile by remember { mutableStateOf("symmetric") }
    var purpose by remember { mutableStateOf("test") }
    var result by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("YKDF", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(
            value = ikmHex,
            onValueChange = { ikmHex = it },
            label = { Text("Input key material (hex)") },
            modifier = Modifier.fillMaxSize(),
        )
        OutlinedTextField(
            value = profile,
            onValueChange = { profile = it },
            label = { Text("Profile") },
        )
        OutlinedTextField(
            value = purpose,
            onValueChange = { purpose = it },
            label = { Text("Purpose") },
        )
        Button(onClick = {
            result = runCatching {
                val ikm = hexToBytes(ikmHex)
                val out = Native.derive(ikm, "hkdf-sha512", profile.trim(), purpose.trim(), 0)
                bytesToHex(out)
            }.getOrElse { "error: ${it.message}" }
        }) {
            Text("Derive")
        }
        if (result.isNotEmpty()) {
            Text("Output", style = MaterialTheme.typography.titleMedium)
            Text(result, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * TODO(nfc): read the YubiKey secret over NFC and feed it into [Native.derive].
 *
 * The transport is `android.nfc.tech.IsoDep` (ISO 14443-4, APDU-native), so
 * both factors travel as APDUs with no libusb involved:
 *  - PIV ECDH on slot 9d: SELECT the PIV applet (A0 00 00 03 08), VERIFY PIN,
 *    then GENERAL AUTHENTICATE (INS 0x87) with the host ephemeral public point;
 *    the card returns the shared point. (yubikit-android: PivSession.)
 *  - HMAC-SHA1 challenge-response on OTP slot 2 over the same IsoDep channel.
 *    (yubikit-android: YubiOtpSession.calculateHmacSha1.)
 * The resulting secret bytes become the `ikm` argument here.
 */
@Suppress("unused")
private fun deriveFromNfc(): Nothing =
    throw NotImplementedError("NFC IsoDep transport: pending on-device hardware step")

private fun hexToBytes(hex: String): ByteArray {
    val clean = hex.trim().replace(" ", "")
    require(clean.length % 2 == 0) { "hex must have an even number of digits" }
    return ByteArray(clean.length / 2) { i ->
        clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }
