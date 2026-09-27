plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.otpfwd.app"
    compileSdk = 37
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "com.otpfwd.app"
        // minSdk 26 (Android 8.0) confirmed with the user — see docs/DESIGN.md §0. Covers the
        // vast majority of devices and has full javax.crypto (AES-GCM, EC KeyAgreement) support.
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests {
            // Nothing under test touches android.* framework classes (see DESIGN.md §2 — crypto/,
            // model/, storage/, and json/ have zero android.* imports specifically so this default
            // stays false and tests exercise real logic rather than framework stubs/defaults).
            isReturnDefaultValues = false
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")

    // WorkManager — approved in docs/DESIGN.md §1/§4 for reliable retry/backoff of the
    // encrypt+POST job handed off from the SMS broadcast receiver.
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    // CameraX + ML Kit Barcode Scanning — approved in docs/DESIGN.md §0 for QR pairing scan.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")

    testImplementation("junit:junit:4.13.2")
}
