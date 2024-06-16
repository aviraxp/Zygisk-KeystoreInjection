-keep class io.github.aviraxp.keystoreinjection.EntryPoint {public <methods>;}
-keep class io.github.aviraxp.keystoreinjection.CustomProvider
-keep class io.github.aviraxp.keystoreinjection.CustomKeyStoreSpi
-keep class io.github.aviraxp.keystoreinjection.CustomKeyStoreKeyPairGeneratorSpi$EC
-keep class io.github.aviraxp.keystoreinjection.CustomKeyStoreKeyPairGeneratorSpi$RSA

-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

-dontwarn javax.naming.**
