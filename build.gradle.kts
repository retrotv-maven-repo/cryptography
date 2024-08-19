import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    java
    jacoco
    kotlin("jvm") version "2.0.0"
    `maven-publish`
    id("org.jetbrains.dokka") version "1.9.20"
    id("org.sonarqube") version "4.0.0.2929"
}

kotlin {
    jvmToolchain(8)
}

jacoco {
    toolVersion = "0.8.12"
}

group = "dev.retrotv"
version = "0.30.0-alpha"

// Github Action 버전 출력용
tasks.register("printVersionName") {
    description = "이 프로젝트의 버전을 출력합니다."
    group = JavaBasePlugin.DOCUMENTATION_GROUP
    println(project.version)
}

repositories {
    mavenCentral()
    maven { setUrl("https://jitpack.io") }
}

val apacheCommonCodec = "1.17.1"
val springSecurityCore = "5.8.11"
val dataUtils = "0.16.0-alpha"
val randomValue = "0.10.0-alpha"
val bouncyCastle = "1.78.1"
val log4j = "2.23.1"
val faker = "1.16.0"
val json = "20240303"
val junit = "5.11.0"

dependencies {
    api("commons-codec:commons-codec:${apacheCommonCodec}")
    api("org.springframework.security:spring-security-core:${springSecurityCore}")
    implementation("com.github.retrotv-maven-repo:data-utils:${dataUtils}")
    implementation("com.github.retrotv-maven-repo:random-value:${randomValue}")
    implementation("org.apache.logging.log4j:log4j-core:${log4j}")

    // Bouncy Castle
    implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastle}")

    testImplementation("io.github.serpro69:kotlin-faker:${faker}")
    testImplementation("org.json:json:${json}")
    testImplementation("org.junit.jupiter:junit-jupiter-api:${junit}")
    testImplementation("org.junit.jupiter:junit-jupiter-params:${junit}")
    testImplementation(kotlin("test"))

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${junit}")
}

tasks {
    compileKotlin {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
    }
    compileTestKotlin {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
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
    finalizedBy("jacocoTestReport")
}

tasks.jacocoTestReport {
    reports {

        // HTML 파일을 생성하도록 설정
        html.required = true

        // SonarQube에서 Jacoco XML 파일을 읽을 수 있도록 설정
        xml.required = true
        csv.required = false
    }
}

sonar {
    properties {
        property("sonar.projectKey", "retrotv-maven-repo_cryptography")
        property("sonar.organization", "retrotv-maven-repo")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.coverage.exclusions", "**/exception/*,**/enums/*")
    }
}
