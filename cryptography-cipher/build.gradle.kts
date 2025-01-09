plugins {
    kotlin("jvm")
}

// kr.re 패키지는 제외하고 빌드
sourceSets {
    main {
        java {
            exclude("kr/re/**")
        }
    }
}

dependencies {
    implementation(project(":cryptography-core"))
}
