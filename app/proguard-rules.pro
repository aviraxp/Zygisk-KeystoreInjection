-keep class es.chiteroman.playintegrityfix.EntryPoint {public <methods>;}
-keep class es.chiteroman.playintegrityfix.CustomProvider
-keep class es.chiteroman.playintegrityfix.CustomKeyStoreSpi
-keep class es.chiteroman.playintegrityfix.CustomKeyStoreKeyPairGeneratorSpi$EC
-keep class es.chiteroman.playintegrityfix.CustomKeyStoreKeyPairGeneratorSpi$RSA

-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

-dontwarn javax.naming.**
