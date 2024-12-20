plugins {
    kotlin("jvm")
}

val springSecurityCore = "6.4.2"

dependencies {
    implementation(project(":cryptography-hash"))
    implementation(project(":cryptography-core"))
    implementation("org.springframework.security:spring-security-core:${springSecurityCore}")
}
