plugins {
    kotlin("jvm")
}

val apacheCommonCodec = "1.17.1"
val springSecurityCore = "5.8.14"
val randomValue = "0.20.0-alpha"

dependencies {
    api("commons-codec:commons-codec:${apacheCommonCodec}")
    api("org.springframework.security:spring-security-core:${springSecurityCore}")
    implementation("com.github.retrotv-maven-repo:random-value:${randomValue}")
}
