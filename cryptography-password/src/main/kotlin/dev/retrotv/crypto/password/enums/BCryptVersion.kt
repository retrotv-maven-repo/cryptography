package dev.retrotv.crypto.password.enums

enum class BCryptVersion(val version: String) {
      `$2A`("$2a")
    , `$2Y`("$2y")
    , `$2B`("$2b");
}