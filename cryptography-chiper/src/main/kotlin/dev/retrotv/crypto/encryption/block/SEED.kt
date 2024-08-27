package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.SEED
import org.bouncycastle.crypto.engines.SEEDEngine

class SEED : BlockCipher() {
    init {
        this.engine = SEEDEngine()
        this.algorithm = SEED
    }
}