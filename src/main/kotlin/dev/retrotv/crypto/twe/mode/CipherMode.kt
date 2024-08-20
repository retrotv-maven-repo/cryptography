package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.enums.Mode

abstract class CipherMode(val mode: Mode, blockCipherAlgorithm: BlockCipherAlgorithm) : TwoWayEncryption {
    val algorithm = blockCipherAlgorithm.algorithm
    protected var engine = blockCipherAlgorithm.engine
}