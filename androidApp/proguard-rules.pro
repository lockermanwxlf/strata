# JNA looks up classes and fields by name through reflection.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-dontwarn java.awt.**

# UniFFI-generated bindings: structures, callbacks and library interfaces are bound by name.
-keep class dev.lockermanwxlf.strata.core.ffi.** { *; }
