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
include(
    "cryptography-core",
    "cryptography-hash",
    "cryptography-cipher"
)
include("cryptography-password")
include("cryptography-password")
