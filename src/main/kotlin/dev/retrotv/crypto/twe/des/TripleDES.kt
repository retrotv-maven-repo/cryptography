package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.BCKeyGenerator
import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.enums.Algorithm

import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.engines.DESedeEngine
import org.bouncycastle.crypto.generators.DESedeKeyGenerator
import java.security.SecureRandom

class TripleDES : CipherAlgorithm(), BCKeyGenerator {

    init {
        this.engine = DESedeEngine()
        this.algorithm = Algorithm.Cipher.TRIPLE_DES
    }

    override fun generateKey(): ByteArray {
        val keyGenerationParam = KeyGenerationParameters(SecureRandom(), 0)
        val keyGenerator = DESedeKeyGenerator()
            keyGenerator.init(keyGenerationParam)

        return keyGenerator.generateKey()
    }
}