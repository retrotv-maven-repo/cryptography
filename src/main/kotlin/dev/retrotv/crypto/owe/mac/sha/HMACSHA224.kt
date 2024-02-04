package dev.retrotv.crypto.owe.mac.sha

import dev.retrotv.crypto.owe.mac.HMAC
import dev.retrotv.enums.Algorithm

class HMACSHA224: HMAC() {

    init {
        this.algorithm = Algorithm.Hmac.HMAC_SHA224
    }
}