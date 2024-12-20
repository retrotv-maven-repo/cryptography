plugins {
    kotlin("jvm")
}

val apacheCommonCodec = "1.17.1"
val randomValue = "1.0.0"

dependencies {
    api("commons-codec:commons-codec:${apacheCommonCodec}")
    implementation("com.github.retrotv-maven-repo:random-value:${randomValue}")
}
