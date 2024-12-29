import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URI

plugins {
    java
    jacoco
    `maven-publish`
    kotlin("jvm") version "2.0.21"
    id("org.jetbrains.dokka") version "1.9.20"
    id("org.sonarqube") version "4.0.0.2929"
}

group = "dev.retrotv"
version = "0.45.5-alpha"

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

    version = project.version
    group = project.group

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

    publishing {
        repositories {
            maven {
                name = "GitHubPackages"
                url = URI("https://maven.pkg.github.com/retrotv-maven-repo/cryptography")
                credentials {
                    username = System.getenv("USERNAME")
                    password = System.getenv("PASSWORD")
                }
            }
        }

        publications {
            register<MavenPublication>("gpr") {
                from(components["java"])
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

    tasks.jar {
        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version
                )
            )
        }
    }
}

sonar {
    properties {
        property("sonar.projectKey", "retrotv-maven-repo_cryptography")
        property("sonar.organization", "retrotv-maven-repo")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.exclusions", "src/main/java/**")
        property("sonar.coverage.exclusions", "src/main/java/**,**/exception/*,**/enums/*,**/util/*,**/BinaryHash.*,**/PlaintextHash.*")
    }
}

kotlin {
    jvmToolchain(8)
}
