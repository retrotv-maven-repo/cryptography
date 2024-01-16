package dev.retrotv.crypto.owe.mac.sha

import dev.retrotv.crypto.owe.mac.HMAC
import dev.retrotv.enums.Algorithm
import javax.crypto.Mac

class HMACSHA1: HMAC() {

    init {
        this.algorithm = Algorithm.Hmac.HMAC_SHA1
        this.mac = Mac.getInstance(this.algorithm.label())
    }
}