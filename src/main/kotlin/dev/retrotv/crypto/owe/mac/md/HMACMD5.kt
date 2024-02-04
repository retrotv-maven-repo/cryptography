package dev.retrotv.crypto.owe.mac.md

import dev.retrotv.crypto.owe.mac.HMAC
import dev.retrotv.enums.Algorithm

class HMACMD5: HMAC() {

    init {
        this.algorithm = Algorithm.Hmac.HMAC_MD5
    }
}