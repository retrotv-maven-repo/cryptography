plugins {
    kotlin("jvm")
}

val springSecurityCore = "5.8.16"

dependencies {
    implementation(project(":cryptography-core"))
}
