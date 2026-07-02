package app.ykdf

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp

// OLED-friendly palette: true black with emerald-400 accents (Tailwind values).
private val Emerald = Color(0xFF34D399) // emerald-400
private val Emerald500 = Color(0xFF10B981) // emerald-500
private val EmeraldDeep = Color(0xFF065F46) // emerald-800
private val Ink = Color(0xFF000000)
private val OnInk = Color(0xFFE6F4EC)

/** Dark theme: pure black surfaces, emerald primary. */
val YkdfColors = darkColorScheme(
    primary = Emerald,
    onPrimary = Ink,
    secondary = Emerald500,
    onSecondary = Ink,
    background = Ink,
    onBackground = OnInk,
    surface = Ink,
    onSurface = OnInk,
    surfaceVariant = Color(0xFF0A0F0D),
    onSurfaceVariant = Color(0xFF8AA79A),
    outline = Color(0xFF1F2A26),
)

/**
 * A full-bleed mesh-style background: true black with three soft emerald radial
 * glows. Compose has no native mesh gradient, so this layers radial gradients to
 * the same effect, which stays cheap and works on every supported API level.
 */
@Composable
fun MeshBackground(content: @Composable () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .drawBehind {
                drawRect(Ink)
                drawRect(
                    Brush.radialGradient(
                        colors = listOf(Emerald.copy(alpha = 0.20f), Color.Transparent),
                        center = Offset(size.width * 0.15f, size.height * 0.05f),
                        radius = size.maxDimension * 0.48f,
                    ),
                )
                drawRect(
                    Brush.radialGradient(
                        colors = listOf(Emerald500.copy(alpha = 0.12f), Color.Transparent),
                        center = Offset(size.width * 0.95f, size.height * 0.22f),
                        radius = size.maxDimension * 0.40f,
                    ),
                )
                drawRect(
                    Brush.radialGradient(
                        colors = listOf(EmeraldDeep.copy(alpha = 0.18f), Color.Transparent),
                        center = Offset(size.width * 0.5f, size.height * 1.10f),
                        radius = size.maxDimension * 0.55f,
                    ),
                )
            },
    ) {
        // Without a Surface here, plain Text/Icon would inherit black content
        // colour; provide the light on-black colour for the whole subtree.
        CompositionLocalProvider(LocalContentColor provides OnInk) {
            content()
        }
    }
}

/** The YKDF mark: the HeroIcons paperclip, stroked in emerald. */
val Paperclip: ImageVector by lazy {
    ImageVector.Builder(
        name = "Paperclip",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).addPath(
        pathData = addPathNodes(
            "m18.375 12.739-7.693 7.693a4.5 4.5 0 0 1-6.364-6.364l10.94-10.94A3 3 0 1 1 19.5 " +
                "7.372L8.552 18.32m.009-.01-.01.01m5.699-9.941-7.81 7.81a1.5 1.5 0 0 0 2.112 2.13",
        ),
        stroke = SolidColor(Emerald),
        strokeLineWidth = 1.5f,
        strokeLineCap = StrokeCap.Round,
        strokeLineJoin = StrokeJoin.Round,
    ).build()
}
