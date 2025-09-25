plugins {
    java
}

val apacheCommonCodec = "1.18.0"
val randomValue = "1.1.3"

dependencies {
    implementation("commons-codec:commons-codec:${apacheCommonCodec}")
    implementation("dev.retrotv:random-value:${randomValue}")
}
