import java.io.ByteArrayOutputStream

plugins {
    id("com.android.application") version "8.5.1" apply false
}

fun String.execute(currentWorkingDir: File = file("./")): String {
    val byteOut = ByteArrayOutputStream()
    project.exec {
        workingDir = currentWorkingDir
        commandLine = split("\\s".toRegex())
        standardOutput = byteOut
    }
    return String(byteOut.toByteArray()).trim()
}

val gitCommitCount = "git rev-list HEAD --count".execute().toInt()
val gitCommitHash = "git rev-parse --verify --short HEAD".execute()

val verName by extra("v0.1.0")
val verCode by extra(gitCommitCount)
val commitHash by extra(gitCommitHash)
