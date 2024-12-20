plugins {
    kotlin("jvm")
}

val springSecurityCore = "5.8.16"

dependencies {
    implementation(project(":cryptography-hash"))
    implementation(project(":cryptography-core"))
    implementation("org.springframework.security:spring-security-core:${springSecurityCore}")
}
