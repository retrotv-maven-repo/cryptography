import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    java
    jacoco
    `maven-publish`
    kotlin("jvm") version "2.1.0"
    id("org.jetbrains.dokka") version "2.0.0"
    id("org.sonarqube") version "4.0.0.2929"
}

group = "dev.retrotv"
version = "0.46.2-alpha"

// Github Action 버전 출력용
tasks.register("printVersionName") {
    description = "이 프로젝트의 버전을 출력합니다."
    group = JavaBasePlugin.DOCUMENTATION_GROUP
    println(project.version)
}

tasks {
    compileKotlin {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
    }
    compileTestKotlin {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

allprojects {
    version = rootProject.version
    group = rootProject.group

    repositories {
        mavenCentral()
        maven { setUrl("https://jitpack.io") }
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "maven-publish")
    apply(plugin = "org.jetbrains.dokka")

    tasks.test {
        useJUnitPlatform()
    }

    val dataUtils = "0.21.6-alpha"
    val log4j = "2.24.1"
    val bouncyCastle = "1.79"
    val json = "20240303"
    val junit = "5.11.2"

    dependencies {
        implementation("com.github.retrotv-maven-repo:data-utils:${dataUtils}")
        implementation("org.apache.logging.log4j:log4j-core:${log4j}")

        // Bouncy Castle
        implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastle}")

        testImplementation(kotlin("test"))
        testImplementation("org.junit.jupiter:junit-jupiter-params:${junit}")
        testImplementation("org.json:json:${json}")
    }

    configure<PublishingExtension> {

        // Github Packages에 배포하기 위한 설정
        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/retrotv-maven-repo/cryptography")
                credentials {
                    username = project.findProperty("gpr.user") as String? ?: System.getenv("USERNAME")
                    password = project.findProperty("gpr.key") as String? ?: System.getenv("PASSWORD")
                }
            }
        }

        publications {
            create<MavenPublication>("maven") {
                groupId = project.group.toString()
                artifactId = project.name
                version = project.version.toString()
                from(components["java"])
            }
        }
    }
}

kotlin {
    jvmToolchain(8)
}

apply(from = "${rootDir}/gradle/sonarcloud.gradle")
apply(from = "${rootDir}/gradle/jacoco.gradle")
