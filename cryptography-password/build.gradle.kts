plugins {
    kotlin("jvm")
}

// org.springframework.security.crypto 패키지를 제외하고 빌드
sourceSets {
    main {
        java {
            exclude("org/springframework/security/crypto/**")
        }
    }
}

dependencies {
    implementation(project(":cryptography-core"))
}
