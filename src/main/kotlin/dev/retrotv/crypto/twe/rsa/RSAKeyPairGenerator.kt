@file:JvmName("RSAKeyPairGenerator")
package dev.retrotv.crypto.twe.rsa

import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import java.security.SecureRandom


fun generateKeyPair(keyLen: Int): AsymmetricCipherKeyPair {
    require(keyLen == 1024 || keyLen == 2048 || keyLen == 3072) {
        getMessage("exception.wrongKeyLength")
    }

    val generator = RSAKeyPairGenerator()
        generator.init(KeyGenerationParameters(SecureRandom(), keyLen))

    return generator.generateKeyPair()
}
