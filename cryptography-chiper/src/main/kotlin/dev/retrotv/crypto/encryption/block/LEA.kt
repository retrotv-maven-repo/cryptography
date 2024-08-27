package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.LEA
import org.bouncycastle.crypto.engines.LEAEngine

class LEA : BlockCipher() {
    init {
        this.engine = LEAEngine()
        this.algorithm = LEA
    }
}