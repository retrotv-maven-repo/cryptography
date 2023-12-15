plugins {
    java
    kotlin("jvm") version "1.9.0"
    `maven-publish`
    id("org.jetbrains.dokka") version "1.9.10"
}

group = "dev.retrotv"
version = "0.20.0-alpha"

// Github Action 버전 출력용
tasks.register("printVersionName") {
    println(project.version)
}

repositories {
    mavenCentral()
    maven { setUrl("https://jitpack.io") }
}

dependencies {
    api("commons-codec:commons-codec:1.16.0")
    api("org.springframework.security:spring-security-core:5.8.8")
    implementation("com.github.retrotv-maven-repo:data-utils:0.13.2-alpha")
    implementation("com.github.retrotv-maven-repo:random-value:0.5.0-alpha")

    // Argon2, SCrypt java.lang.NoClassDefFoundError 방지용
    implementation("org.bouncycastle:bcprov-jdk18on:1.76")
    implementation("org.apache.logging.log4j:log4j-core:2.20.0")

    testImplementation("org.json:json:20231013")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.0")
    testImplementation(kotlin("test"))
}

tasks {
    compileKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
    compileTestKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = project.group.toString()
            artifactId = "cryptography"
            version = project.version.toString()

            from(components["java"])
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(8)
}