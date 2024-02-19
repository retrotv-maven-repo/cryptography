package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.SEEDEngine

class SEED : BlockCipherAlgorithm() {

    init {
        this.engine = SEEDEngine()
        this.algorithm = Algorithm.Cipher.SEED
    }
}