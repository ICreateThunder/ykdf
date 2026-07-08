package app.ykdf

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.ykdf.nfc.YubiKeyNfc
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/** The app's per-use-case modes. Recipes and future extensions (x509, signing) join this list later. */
private enum class Mode(val label: String) {
    Derive("Derive"),
    WireGuard("WireGuard"),
}

/**
 * Tap a YubiKey, read the secret over NFC (custom APDU handler), run the
 * derivation in ykdf-core via JNI, and show the result for the selected mode.
 *
 * Derive mode shows any profile's secret + public key. WireGuard mode renders a
 * full config from an x25519 key via `Native.wgConfig`, byte-identical to
 * `ykdf wg config`, with Copy / Share / QR for handoff to the WireGuard app.
 */
class MainActivity : ComponentActivity() {
    private var nfcAdapter: NfcAdapter? = null

    // Lets the user save the rendered config as a file the WireGuard app imports.
    // Registered here (before STARTED) so the callback can write the current
    // config to the chosen location.
    private val saveConfig =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            uri?.let { writeConfigTo(it) }
        }

    // Shared inputs.
    private val pin = mutableStateOf("")
    private val layered = mutableStateOf(false)
    private val purpose = mutableStateOf("wg-home")
    private val mode = mutableStateOf(Mode.Derive)
    private val status = mutableStateOf("Tap your YubiKey to the back of the phone")

    // Derive mode.
    private val profile = mutableStateOf("x25519")
    private val output = mutableStateOf("")
    private val showSecret = mutableStateOf(false)
    private val publicKey = mutableStateOf("")

    // WireGuard mode inputs.
    private val wgAddress = mutableStateOf("10.0.0.2/24")
    private val wgDns = mutableStateOf("")
    private val wgPeerPubkey = mutableStateOf("")
    private val wgEndpoint = mutableStateOf("")
    private val wgAllowedIps = mutableStateOf("0.0.0.0/0")
    private val wgKeepalive = mutableStateOf("")

    // WireGuard mode output. The config embeds the private key, so it stays
    // masked until the user reveals it; the QR is the WireGuard-app import path.
    private val wgConfig = mutableStateOf("")
    private val showConfig = mutableStateOf(false)
    private val wgQr = mutableStateOf<Bitmap?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val transparentDark = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = transparentDark, navigationBarStyle = transparentDark)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        setContent {
            MaterialTheme(colorScheme = YkdfColors) {
                MeshBackground {
                    MainScreen(
                        pin, layered, purpose, mode, status,
                        profile, output, showSecret, publicKey,
                        wgAddress, wgDns, wgPeerPubkey, wgEndpoint, wgAllowedIps, wgKeepalive,
                        wgConfig, showConfig, wgQr,
                        onSaveConfig = { saveConfig.launch("client.conf") },
                    )
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
            when (mode.value) {
                Mode.Derive -> runDerive(ikm)
                Mode.WireGuard -> runWireGuard(ikm)
            }
            ikm.fill(0)
        } catch (e: Exception) {
            when (mode.value) {
                Mode.Derive -> postDerive("Error: ${e.message}", "", "")
                Mode.WireGuard -> postWireGuard("Error: ${e.message}", "", null)
            }
        } finally {
            pinBytes.fill(0)
            runCatching { isoDep.close() }
        }
    }

    private fun runDerive(ikm: ByteArray) {
        val prof = profile.value.trim()
        val purp = purpose.value.trim()
        // Empty pipeline => the profile's default, matching the CLI.
        val secret = Native.derive(ikm, "", prof, purp, 0)
        val pub = try {
            Native.derivePublic(ikm, "", prof, purp, 0)
        } catch (e: Exception) {
            "" // symmetric/raw have no public key
        }
        val hex = bytesToHex(secret)
        val size = secret.size
        secret.fill(0)
        postDerive("Derived $size bytes", hex, pub)
    }

    private fun runWireGuard(ikm: ByteArray) {
        val hasPeerKey = wgPeerPubkey.value.isNotBlank()
        val hasPeerFields = wgEndpoint.value.isNotBlank() ||
            wgAllowedIps.value.isNotBlank() ||
            wgKeepalive.value.isNotBlank()
        val config = Native.wgConfig(
            ikm,
            purpose.value.trim(),
            0,
            splitCsv(wgAddress.value),
            -1,
            splitCsv(wgDns.value),
            -1,
            wgPeerPubkey.value.trim(),
            wgEndpoint.value.trim(),
            splitCsv(wgAllowedIps.value),
            wgKeepalive.value.trim().toIntOrNull() ?: -1,
        )
        val qr = runCatching { qrBitmap(config, 720) }.getOrNull()
        // A [Peer] needs a public key; the endpoint/AllowedIPs/keepalive fields
        // are dropped without one. Say so rather than silently omitting them.
        val note = if (hasPeerFields && !hasPeerKey) {
            "Config ready. The [Peer] section was omitted: add the peer's public key to include it."
        } else {
            "WireGuard config ready"
        }
        postWireGuard(note, config, qr)
    }

    private fun post(message: String) = runOnUiThread { status.value = message }

    private fun postDerive(message: String, hex: String, pub: String) = runOnUiThread {
        status.value = message
        output.value = hex
        publicKey.value = pub
        showSecret.value = false
    }

    private fun postWireGuard(message: String, config: String, qr: Bitmap?) = runOnUiThread {
        status.value = message
        wgConfig.value = config
        wgQr.value = qr
        showConfig.value = false
    }

    /** Write the current WireGuard config to the user-chosen document URI. */
    private fun writeConfigTo(uri: Uri) {
        val result = runCatching {
            contentResolver.openOutputStream(uri)?.use { it.write(wgConfig.value.toByteArray()) }
                ?: error("could not open the chosen location")
        }
        post(result.fold({ "Saved client.conf" }, { "Save failed: ${it.message}" }))
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}

/** Split a comma-separated field into a trimmed, non-empty array for the JNI arrays. */
private fun splitCsv(value: String): Array<String> =
    value.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toTypedArray()

/** Encode `text` as a black-on-white QR bitmap of `size` x `size` pixels. */
private fun qrBitmap(text: String, size: Int): Bitmap {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bitmap.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
        }
    }
    return bitmap
}

@OptIn(ExperimentalMaterial3Api::class)
@Suppress("ComposableNaming", "LongParameterList")
@androidx.compose.runtime.Composable
private fun MainScreen(
    pin: MutableState<String>,
    layered: MutableState<Boolean>,
    purpose: MutableState<String>,
    mode: MutableState<Mode>,
    status: MutableState<String>,
    profile: MutableState<String>,
    output: MutableState<String>,
    showSecret: MutableState<Boolean>,
    publicKey: MutableState<String>,
    wgAddress: MutableState<String>,
    wgDns: MutableState<String>,
    wgPeerPubkey: MutableState<String>,
    wgEndpoint: MutableState<String>,
    wgAllowedIps: MutableState<String>,
    wgKeepalive: MutableState<String>,
    wgConfig: MutableState<String>,
    showConfig: MutableState<Boolean>,
    wgQr: MutableState<Bitmap?>,
    onSaveConfig: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .safeDrawingPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = Paperclip,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(36.dp),
            )
            Text(
                "YKDF",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }

        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            val modes = Mode.entries
            modes.forEachIndexed { index, m ->
                SegmentedButton(
                    selected = mode.value == m,
                    onClick = { mode.value = m },
                    shape = SegmentedButtonDefaults.itemShape(index, modes.size),
                ) {
                    Text(m.label)
                }
            }
        }

        OutlinedTextField(
            value = pin.value,
            onValueChange = { pin.value = it },
            label = { Text("PIV PIN") },
            visualTransformation = PasswordVisualTransformation(),
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

        when (mode.value) {
            Mode.Derive -> DeriveSection(profile, output, showSecret, publicKey)
            Mode.WireGuard -> WireGuardSection(
                wgAddress, wgDns, wgPeerPubkey, wgEndpoint, wgAllowedIps, wgKeepalive,
                wgConfig, showConfig, wgQr, onSaveConfig,
            )
        }

        Text(status.value, style = MaterialTheme.typography.bodyMedium)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Suppress("ComposableNaming")
@androidx.compose.runtime.Composable
private fun DeriveSection(
    profile: MutableState<String>,
    output: MutableState<String>,
    showSecret: MutableState<Boolean>,
    publicKey: MutableState<String>,
) {
    // The picker is driven by ykdf-core (via JNI) so it never drifts from the
    // profiles the core supports. Fall back to a single entry if the native call
    // fails, so the field is never empty.
    val profiles = remember {
        runCatching { Native.profiles().toList() }.getOrDefault(listOf("x25519"))
    }
    val profileExpanded = remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = profileExpanded.value,
        onExpandedChange = { profileExpanded.value = it },
    ) {
        OutlinedTextField(
            value = profile.value,
            onValueChange = {},
            readOnly = true,
            label = { Text("Profile") },
            trailingIcon = {
                ExposedDropdownMenuDefaults.TrailingIcon(expanded = profileExpanded.value)
            },
            modifier = Modifier
                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                .fillMaxWidth(),
        )
        ExposedDropdownMenu(
            expanded = profileExpanded.value,
            onDismissRequest = { profileExpanded.value = false },
        ) {
            profiles.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        profile.value = option
                        profileExpanded.value = false
                    },
                )
            }
        }
    }

    val clipboard = LocalClipboardManager.current
    if (output.value.isNotEmpty()) {
        Text("Private key (keep secret)", style = MaterialTheme.typography.titleMedium)
        Text(
            if (showSecret.value) output.value else "•••• hidden ••••",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { showSecret.value = !showSecret.value }) {
                Text(if (showSecret.value) "Hide" else "Show")
            }
            TextButton(onClick = { clipboard.setText(AnnotatedString(output.value)) }) {
                Text("Copy")
            }
        }
    }
    if (publicKey.value.isNotEmpty()) {
        Text("Public key", style = MaterialTheme.typography.titleMedium)
        Text(publicKey.value, style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { clipboard.setText(AnnotatedString(publicKey.value)) }) {
            Text("Copy")
        }
    }
}

@Suppress("ComposableNaming", "LongParameterList")
@androidx.compose.runtime.Composable
private fun WireGuardSection(
    wgAddress: MutableState<String>,
    wgDns: MutableState<String>,
    wgPeerPubkey: MutableState<String>,
    wgEndpoint: MutableState<String>,
    wgAllowedIps: MutableState<String>,
    wgKeepalive: MutableState<String>,
    wgConfig: MutableState<String>,
    showConfig: MutableState<Boolean>,
    wgQr: MutableState<Bitmap?>,
    onSaveConfig: () -> Unit,
) {
    Text("Interface", style = MaterialTheme.typography.titleMedium)
    WgField(wgAddress, "Address (CIDR, comma-separated)")
    WgField(wgDns, "DNS (optional, comma-separated)")

    Text("Peer", style = MaterialTheme.typography.titleMedium)
    Text(
        "A [Peer] section is included only when a public key is set.",
        style = MaterialTheme.typography.bodySmall,
    )
    WgField(wgPeerPubkey, "Peer public key")
    WgField(wgEndpoint, "Endpoint host:port")
    WgField(wgAllowedIps, "AllowedIPs (CIDR, comma-separated)")
    WgField(wgKeepalive, "Persistent keepalive seconds")

    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    if (wgConfig.value.isNotEmpty()) {
        Text(
            "WireGuard config (contains private key)",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            if (showConfig.value) wgConfig.value else "•••• hidden ••••",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { showConfig.value = !showConfig.value }) {
                Text(if (showConfig.value) "Hide" else "Show")
            }
            TextButton(onClick = { clipboard.setText(AnnotatedString(wgConfig.value)) }) {
                Text("Copy")
            }
            TextButton(onClick = {
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, wgConfig.value)
                }
                context.startActivity(Intent.createChooser(send, "Share WireGuard config"))
            }) {
                Text("Share")
            }
            TextButton(onClick = onSaveConfig) {
                Text("Save .conf")
            }
        }
        // The QR encodes the private key, so keep it hidden until the same
        // reveal that shows the config text.
        if (showConfig.value) {
            wgQr.value?.let { bitmap ->
                Text(
                    "Scan in the WireGuard app to import",
                    style = MaterialTheme.typography.bodySmall,
                )
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "WireGuard config QR code",
                    modifier = Modifier.size(240.dp),
                )
            }
        }
    }
}

@Suppress("ComposableNaming")
@androidx.compose.runtime.Composable
private fun WgField(state: MutableState<String>, label: String) {
    OutlinedTextField(
        value = state.value,
        onValueChange = { state.value = it },
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
    )
}
