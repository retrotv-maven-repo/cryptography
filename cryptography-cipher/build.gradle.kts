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

val bouncyCastle = "1.79"

dependencies {
    implementation(project(":cryptography-core"))
    implementation("org.bouncycastle:bcprov-jdk18on:${bouncyCastle}")
}
