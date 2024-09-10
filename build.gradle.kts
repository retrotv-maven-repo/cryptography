import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    java
    jacoco
    `java-library`
    `maven-publish`
    kotlin("jvm") version "2.0.10"
    id("org.jetbrains.dokka") version "1.9.20"
    id("org.sonarqube") version "4.0.0.2929"
}

group = "dev.retrotv"
version = "0.42.10-alpha"

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
    version = project.version
    group = project.group

    repositories {
        mavenCentral()
        maven { setUrl("https://jitpack.io") }
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "jacoco")
    apply(plugin = "maven-publish")

    jacoco {
        toolVersion = "0.8.12"
    }

    tasks.test {
        useJUnitPlatform()
        finalizedBy("jacocoTestReport")
    }

    tasks.jacocoTestReport {
        reports {
            html.required.set(true)
            xml.required.set(true)
            csv.required.set(false)
        }
    }

    jacoco {
        toolVersion = "0.8.12"
    }

    val dataUtils = "0.16.0-alpha"
    val log4j = "2.23.1"
    val bouncyCastle = "1.78.1"
    val json = "20240303"
    val junit = "5.11.0"

    dependencies {
        implementation("com.github.retrotv-maven-repo:data-utils:${dataUtils}")
        implementation("org.apache.logging.log4j:log4j-core:${log4j}")

        // Bouncy Castle
        implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastle}")

        testImplementation(kotlin("test"))
        testImplementation("org.junit.jupiter:junit-jupiter-params:${junit}")
        testImplementation("org.json:json:${json}")
    }

    publishing {
        publications {
            create<MavenPublication>("maven") {
                groupId = project.group.toString()
                artifactId = project.name.toString()
                version = project.version.toString()
                from(components["java"])
            }
        }
    }
}

sonar {
    properties {
        property("sonar.projectKey", "retrotv-maven-repo_cryptography")
        property("sonar.organization", "retrotv-maven-repo")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.exclusions", "src/main/java/**")
        property("sonar.coverage.exclusions", "**/exception/*,**/enums/*,src/main/java/**")
    }
}

kotlin {
    jvmToolchain(8)
}
