# LibDia ProGuard Rules
# Add these rules to your app/proguard-rules.pro file

# ==================== Core LibDia Rules ====================

# Keep all public classes and methods in LibDia
-keep class io.github.lokingdav.libdia.LibDia {
    public *;
}

# Keep all native methods (JNI functions)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep DiaConfig class and all its methods
-keep class io.github.lokingdav.libdia.DiaConfig {
    public *;
    private <init>(...);
}

# Keep CallState class and all its methods
-keep class io.github.lokingdav.libdia.CallState {
    public *;
    private <init>(...);
}

# Keep DiaMessage class and all its methods
-keep class io.github.lokingdav.libdia.DiaMessage {
    public *;
    private <init>(...);
}

# Keep RemoteParty data class
-keep class io.github.lokingdav.libdia.RemoteParty {
    public *;
}

# Keep Enrollment object
-keep class io.github.lokingdav.libdia.Enrollment {
    public *;
}

# ==================== Reflection Support ====================

# LibDia uses reflection to create DiaConfig instances
# Keep constructors that may be called via reflection
-keepclassmembers class io.github.lokingdav.libdia.DiaConfig {
    private <init>(long);
}

-keepclassmembers class io.github.lokingdav.libdia.CallState {
    private <init>(long);
}

-keepclassmembers class io.github.lokingdav.libdia.DiaMessage {
    private <init>(long);
}

# ==================== AutoCloseable Support ====================

# Keep close() methods for AutoCloseable classes
-keepclassmembers class * implements java.lang.AutoCloseable {
    public void close();
}

# ==================== Data Classes ====================

# Keep data class generated methods
-keepclassmembers class io.github.lokingdav.libdia.RemoteParty {
    public ** component1();
    public ** component2();
    public ** copy(...);
}

# ==================== JNI Support ====================

# Don't warn about native method implementations
-dontwarn io.github.lokingdav.libdia.LibDia

# Keep native library loading
-keepclassmembers class * {
    static {
        java.lang.System.loadLibrary(...);
    }
}

# ==================== Exceptions ====================

# Keep exception classes
-keep public class * extends java.lang.Exception

# Keep custom exception messages
-keepclassmembers class * extends java.lang.Exception {
    public <init>(java.lang.String);
}

# ==================== Serialization Support ====================

# If using JSON serialization for configs/keys
# Keep field names for JSON mapping
-keepclassmembers class io.github.lokingdav.libdia.** {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Keep JSON serializable classes
-keep class * implements java.io.Serializable {
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ==================== Optimization Rules ====================

# Don't optimize native method calls
-keep,allowobfuscation,allowshrinking class io.github.lokingdav.libdia.** {
    native <methods>;
}

# ==================== Debugging Support ====================

# Keep source file names and line numbers for stack traces
-keepattributes SourceFile,LineNumberTable

# Keep parameter names for better debugging
-keepattributes *Annotation*,Signature,Exception

# ==================== Native Library Rules ====================

# Ensure native libraries are included in APK
-keep class io.github.lokingdav.libdia.LibDia {
    static {
        java.lang.System.loadLibrary("dia_jni");
    }
}

# ==================== Additional Safety Rules ====================

# Don't warn about missing classes (MCL library dependencies)
-dontwarn org.bouncycastle.**
-dontwarn javax.crypto.**

# Keep everything if debugging ProGuard issues
# Uncomment these lines if you encounter issues:
# -keep class io.github.lokingdav.libdia.** { *; }
# -keepclassmembers class io.github.lokingdav.libdia.** { *; }

# ==================== R8 Full Mode Support ====================

# R8 full mode compatibility
-keep,allowobfuscation,allowshrinking class io.github.lokingdav.libdia.**
-keep,allowobfuscation,allowshrinking interface io.github.lokingdav.libdia.**

# ==================== End LibDia Rules ====================
