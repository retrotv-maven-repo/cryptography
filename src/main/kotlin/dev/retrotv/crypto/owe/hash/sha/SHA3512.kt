package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.enums.Algorithm.Hash.SHA3512

class SHA3512 : Hash() {


    init {
        this.algorithm = SHA3512
    }
}