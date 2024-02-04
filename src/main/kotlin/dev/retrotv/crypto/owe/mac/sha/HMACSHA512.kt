package dev.retrotv.crypto.owe.mac.sha

import dev.retrotv.crypto.owe.mac.HMAC
import dev.retrotv.enums.Algorithm

class HMACSHA512: HMAC() {

    init {
        this.algorithm = Algorithm.Hmac.HMAC_SHA512
    }
}