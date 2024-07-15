import android.databinding.tool.ext.capitalizeUS

plugins {
    id("com.android.application")
}

val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra

android {
    namespace = "io.github.aviraxp.keystoreinjection"
    compileSdk = 35
    ndkVersion = "26.3.11579264"
    buildToolsVersion = "35.0.0"

    buildFeatures {
        prefab = true
    }

    defaultConfig {
        applicationId = "io.github.aviraxp.keystoreinjection"
        minSdk = 30
        targetSdk = 35
        versionCode = verCode
        versionName = verName

        packaging {
            resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
        }

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
                cppFlags += "-fno-exceptions"
                cppFlags += "-fno-rtti"
                cppFlags += "-fvisibility=hidden"
                cppFlags += "-fvisibility-inlines-hidden"
                cppFlags += "-std=c++20"
            }
        }
    }

    buildTypes {
        debug {
            multiDexEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            multiDexEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation("dev.rikka.ndk.thirdparty:cxx:1.2.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}

androidComponents.onVariants { variant ->
    afterEvaluate {
        val variantLowered = variant.name.lowercase()
        val variantCapped = variant.name.capitalizeUS()
        tasks.register("updateModuleProp$variantCapped") {
            group = "Zygisk"
            dependsOn("assemble$variantCapped")
            doLast {
                val versionName = project.android.defaultConfig.versionName
                val versionCode = project.android.defaultConfig.versionCode
                val modulePropFile = project.rootDir.resolve("module/module.prop")
                var content = modulePropFile.readText()
                content = content.replace(Regex("version=.*"), "version=$versionName")
                content = content.replace(Regex("versionCode=.*"), "versionCode=$versionCode")
                modulePropFile.writeText(content)
            }
        }

        tasks.register("copyFiles$variantCapped") {
            group = "Zygisk"
            dependsOn("updateModuleProp$variantCapped")
            doLast {
                val moduleFolder = project.rootDir.resolve("module")
                val dexFile =
                    if (variantLowered == "release")
                        project.layout.buildDirectory.get().asFile.resolve("intermediates/dex/$variantLowered/minify${variantCapped}WithR8/classes.dex")
                    else
                        project.layout.buildDirectory.get().asFile.resolve("intermediates/dex/$variantLowered/mergeDex$variantCapped/classes.dex")
                val soDir =
                    project.layout.buildDirectory.get().asFile.resolve("intermediates/stripped_native_libs/$variantLowered/strip${variantCapped}DebugSymbols/out/lib")
                dexFile.copyTo(moduleFolder.resolve("classes.dex"), overwrite = true)
                soDir.walk().filter { it.isFile && it.extension == "so" }.forEach { soFile ->
                    val abiFolder = soFile.parentFile.name
                    val destination = moduleFolder.resolve("zygisk/$abiFolder.so")
                    soFile.copyTo(destination, overwrite = true)
                }
            }
        }

        tasks.register<Zip>("zip$variantCapped") {
            group = "Zygisk"
            dependsOn("copyFiles$variantCapped")
            archiveFileName.set("KeystoreInjection-${project.android.defaultConfig.versionName}-${project.android.defaultConfig.versionCode}-$commitHash-${variantLowered}.zip")
            destinationDirectory.set(project.rootDir.resolve("out"))
            from(project.rootDir.resolve("module"))
        }
    }
}
