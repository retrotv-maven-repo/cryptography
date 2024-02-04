package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.BCKeyGenerator
import dev.retrotv.crypto.twe.CipherAlgorithm

import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.generators.DESedeKeyGenerator
import java.security.SecureRandom

abstract class TripleDES : CipherAlgorithm(), BCKeyGenerator {

    override fun generateKey(): ByteArray {
        val keyGenerationParam = KeyGenerationParameters(SecureRandom(), 0)
        val keyGenerator = DESedeKeyGenerator()
            keyGenerator.init(keyGenerationParam)

        return keyGenerator.generateKey()
    }
}