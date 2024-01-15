package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.Algorithm.Hash.SHA3256

class SHA3256 : Hash() {

    init {
        this.algorithm = SHA3256
    }
}