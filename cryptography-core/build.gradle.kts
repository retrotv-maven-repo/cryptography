plugins {
    kotlin("jvm")
}

val apacheCommonCodec = "1.18.0"
val randomValue = "1.1.2"

dependencies {
    api("commons-codec:commons-codec:${apacheCommonCodec}")
    implementation("dev.retrotv:random-value:${randomValue}")
}
