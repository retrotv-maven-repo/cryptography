import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URI

plugins {
    java
    jacoco
    `maven-publish`
    kotlin("jvm") version "2.1.21"
    id("com.vanniktech.maven.publish") version "0.32.0"
    id("org.jetbrains.dokka") version "2.0.0"
    id("org.sonarqube") version "4.0.0.2929"
}

group = "dev.retrotv"
version = "0.51.1-alpha"

tasks.withType(JavaCompile::class) {
    options.encoding = "UTF-8"
}

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
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "maven-publish")
    apply(plugin = "org.jetbrains.dokka")
    apply(plugin = "com.vanniktech.maven.publish")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(8))
        }
    }

    tasks.test {
        useJUnitPlatform()
    }

    val dataUtils = "0.23.3-alpha"
    val slf4j = "2.0.17"
    val log4j = "2.25.1"
    val bouncyCastle = "1.81"
    val json = "20250517"
    val junit = "5.13.1"

    dependencies {
        configurations.all {
            exclude(group = "com.fasterxml.jackson.module", module = "jackson-module-kotlin")
        }

        implementation("dev.retrotv:data-utils:${dataUtils}")

        // Logger
        compileOnly("org.slf4j:slf4j-api:${slf4j}")
        testImplementation("org.slf4j:slf4j-api:${slf4j}")
        testImplementation("org.apache.logging.log4j:log4j-core:${log4j}")
        testImplementation("org.apache.logging.log4j:log4j-slf4j2-impl:${log4j}")

        // Bouncy Castle
        implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastle}")

        testImplementation(kotlin("test"))
        testImplementation("org.junit.jupiter:junit-jupiter:${junit}")
        testImplementation("org.json:json:${json}")
    }

    mavenPublishing {
        publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

        signAllPublications()

        coordinates(group.toString(), project.name, version.toString())

        pom {
            name.set("cryptography")
            description.set("Java 암호화 라이브러리 입니다.")
            inceptionYear.set("2025")
            url.set("https://github.com/retrotv-maven-repo/cryptography")

            licenses {
                license {
                    name.set("The Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }

            developers {
                developer {
                    id.set("yjj8353")
                    name.set("JaeJun Yang")
                    email.set("yjj8353@gmail.com")
                }
            }

            scm {
                connection.set("scm:git:git://github.com/retrotv-maven-repo/cryptography.git")
                developerConnection.set("scm:git:ssh://github.com/retrotv-maven-repo/cryptography.git")
                url.set("https://github.com/retrotv-maven-repo/cryptography.git")
            }
        }

        publishing {
            repositories {

                // Github Packages에 배포하기 위한 설정
                maven {
                    name = "GitHubPackages"
                    url = URI("https://maven.pkg.github.com/retrotv-maven-repo/cryptography")
                    credentials {
                        username = System.getenv("USERNAME")
                        password = System.getenv("PASSWORD")
                    }
                }
            }
        }
    }

    tasks.withType<Sign>().configureEach {
        onlyIf {
            // 로컬 및 깃허브 패키지 배포 시에는 서명하지 않도록 설정
            val graph = gradle.taskGraph
            !graph.allTasks.any { task ->
                task.path.endsWith("PublicationToMavenLocal") || task.path.endsWith("PublicationToGitHubPackagesRepository")
            }
        }
    }
}

kotlin {
    jvmToolchain(8)
}

apply(from = "${rootDir}/gradle/sonarcloud.gradle")
apply(from = "${rootDir}/gradle/jacoco.gradle")
