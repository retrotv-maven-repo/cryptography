plugins {
    java
}

val apacheCommonCodec = "1.18.0"

dependencies {
    implementation(project(":cryptography-core"))
    implementation("commons-codec:commons-codec:${apacheCommonCodec}")
}
