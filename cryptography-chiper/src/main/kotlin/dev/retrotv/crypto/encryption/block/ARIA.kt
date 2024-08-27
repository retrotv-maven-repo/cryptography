package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.ARIA
import org.bouncycastle.crypto.engines.ARIAEngine

class ARIA : BlockCipher() {
    init {
        this.engine = ARIAEngine()
        this.algorithm = ARIA
    }
}