plugins {
    kotlin("jvm")
}

val springSecurityCore = "5.8.16"

dependencies {
    implementation(project(":cryptography-core"))
    compileOnly("org.springframework.security:spring-security-core:${springSecurityCore}")
}
