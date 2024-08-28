package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.SERPENT
import org.bouncycastle.crypto.engines.SerpentEngine

class Serpent : BlockCipher() {
    init {
        this.engine = SerpentEngine()
        this.algorithm = SERPENT
    }
}