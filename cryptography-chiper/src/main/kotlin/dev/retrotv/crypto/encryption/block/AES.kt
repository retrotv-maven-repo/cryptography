package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher.AES
import org.bouncycastle.crypto.engines.AESEngine

class AES : BlockCipher() {
    init {
        this.engine = AESEngine.newInstance()
        this.algorithm = AES
    }
}