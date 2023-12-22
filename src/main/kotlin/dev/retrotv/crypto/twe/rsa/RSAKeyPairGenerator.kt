package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.twe.KeyPairGenerator
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import java.security.KeyPair
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

class RSAKeyPairGenerator(keyLen: Int) : KeyPairGenerator {
    private val keyLen: Int

    init {
        require(keyLen == 1024 || keyLen == 2048) {
            "해당 알고리즘이 지원하지 않는 키 길이 입니다."
        }

        if (keyLen == 1024) {
            log.debug("key 길이는 2048bit 이상을 권장합니다.")
        }

        this.keyLen = keyLen
    }

    @Throws(KeyGenerateException::class)
    override fun generateKeyPair(): KeyPair {
        return try {
            val keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(keyLen, SecureRandom())
            keyPairGenerator.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    companion object {
        private val log = LogManager.getLogger()
    }
}
