pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "cryptography"
include("cryptography-core")
include("cryptography-hash")
include("cryptography-chiper")
include("cryptography-password")
