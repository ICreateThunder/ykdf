// Version pins are a coherent starting point but were NOT executed in the spike
// environment (no network for AGP/Compose artifacts). Reconcile against the
// installed SDK and Gradle in Android Studio; see apps/android/README.md.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
