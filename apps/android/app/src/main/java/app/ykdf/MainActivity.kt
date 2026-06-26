package app.ykdf

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.ykdf.nfc.YubiKeyNfc

/**
 * Spike UI: tap a YubiKey, read the secret over NFC (custom APDU handler), run
 * the derivation in ykdf-core via JNI, and show the result.
 *
 * The derived bytes are provably the same as the CLI's for the same device, so
 * this is the on-device half of the shared-derivation acceptance test.
 */
class MainActivity : ComponentActivity() {
    private var nfcAdapter: NfcAdapter? = null

    // State shared between Compose and the NFC reader callback (a binder thread).
    private val pin = mutableStateOf("")
    private val profile = mutableStateOf("x25519")
    private val purpose = mutableStateOf("wg-home")
    private val layered = mutableStateOf(false)
    private val status = mutableStateOf("Tap your YubiKey to the back of the phone")
    private val output = mutableStateOf("")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxWidth()) {
                    DeriveScreen(pin, profile, purpose, layered, status, output)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        nfcAdapter?.enableReaderMode(this, ::onTag, flags, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    /** Reader-mode callback. Runs off the UI thread, so blocking I/O is fine. */
    private fun onTag(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            post("Not an ISO-DEP tag (is this a YubiKey 5 NFC?)")
            return
        }
        post("Reading YubiKey...")
        val pinBytes = pin.value.toByteArray(Charsets.US_ASCII)
        try {
            val ikm = YubiKeyNfc.deriveIkm(isoDep, pinBytes, layered.value)
            // Empty pipeline => the profile's default, matching the CLI.
            val secret = Native.derive(ikm, "", profile.value.trim(), purpose.value.trim(), 0)
            ikm.fill(0)
            val hex = bytesToHex(secret)
            val size = secret.size
            secret.fill(0)
            postResult("Derived $size bytes", hex)
        } catch (e: Exception) {
            postResult("Error: ${e.message}", "")
        } finally {
            pinBytes.fill(0)
            runCatching { isoDep.close() }
        }
    }

    private fun post(message: String) = runOnUiThread { status.value = message }

    private fun postResult(message: String, hex: String) = runOnUiThread {
        status.value = message
        output.value = hex
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}

@Suppress("ComposableNaming")
@androidx.compose.runtime.Composable
private fun DeriveScreen(
    pin: MutableState<String>,
    profile: MutableState<String>,
    purpose: MutableState<String>,
    layered: MutableState<Boolean>,
    status: MutableState<String>,
    output: MutableState<String>,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .safeDrawingPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("YKDF", style = MaterialTheme.typography.headlineSmall)

        OutlinedTextField(
            value = pin.value,
            onValueChange = { pin.value = it },
            label = { Text("PIV PIN") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = profile.value,
            onValueChange = { profile.value = it },
            label = { Text("Profile") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = purpose.value,
            onValueChange = { purpose.value = it },
            label = { Text("Purpose") },
            modifier = Modifier.fillMaxWidth(),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = layered.value, onCheckedChange = { layered.value = it })
            Text("Layered (PIV + HMAC slot 2)")
        }

        Text(status.value, style = MaterialTheme.typography.bodyMedium)
        if (output.value.isNotEmpty()) {
            Text("Output", style = MaterialTheme.typography.titleMedium)
            Text(output.value, style = MaterialTheme.typography.bodySmall)
        }
    }
}
