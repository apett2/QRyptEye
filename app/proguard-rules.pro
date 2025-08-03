# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Keep cryptographic classes
-keep class com.qrypteye.app.crypto.** { *; }
-keep class org.bouncycastle.** { *; }

# Keep QR code related classes
-keep class com.qrypteye.app.qr.** { *; }
-keep class com.google.zxing.** { *; }

# Keep data models
-keep class com.qrypteye.app.data.** { *; }

# Keep JSON serialization
-keep class com.google.gson.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# Keep Android specific classes
-keep class androidx.** { *; }
-keep class com.google.android.material.** { *; } 