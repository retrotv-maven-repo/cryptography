plugins {
    kotlin("jvm")
}

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
