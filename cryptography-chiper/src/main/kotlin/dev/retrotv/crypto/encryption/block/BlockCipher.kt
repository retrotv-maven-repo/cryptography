package dev.retrotv.crypto.encryption.block

import dev.retrotv.crypto.enums.ECipher
import org.bouncycastle.crypto.BlockCipher

abstract class BlockCipher {
    lateinit var engine: BlockCipher
    lateinit var algorithm: ECipher
}