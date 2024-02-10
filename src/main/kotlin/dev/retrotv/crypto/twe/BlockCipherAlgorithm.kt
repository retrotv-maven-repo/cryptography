package dev.retrotv.crypto.twe

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.BlockCipher

abstract class BlockCipherAlgorithm {
    lateinit var engine: BlockCipher
    lateinit var algorithm: Algorithm.Cipher
}