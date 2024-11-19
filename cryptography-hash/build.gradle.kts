plugins {
    kotlin("jvm")
}

val springSecurityCore = "5.8.15"

dependencies {
    implementation(project(":cryptography-core"))
    api("org.springframework.security:spring-security-core:${springSecurityCore}")
}
