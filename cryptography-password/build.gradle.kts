plugins {
    kotlin("jvm")
}

val springSecurityCore = "5.8.14"

dependencies {
    api("org.springframework.security:spring-security-core:${springSecurityCore}")
    implementation(project(":cryptography-hash"))
    implementation(project(":cryptography-core"))
}
