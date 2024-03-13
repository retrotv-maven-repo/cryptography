package dev.retrotv.crypto.twe.algorithm.stream

import dev.retrotv.crypto.twe.algorithm.StreamCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.RC4Engine

class RC4 : StreamCipherAlgorithm() {

    init {
        this.engine = RC4Engine()
        this.algorithm = Algorithm.Cipher.RC4
    }
}