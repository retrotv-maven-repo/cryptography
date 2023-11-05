package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.KeyPairGenerator
import org.apache.logging.log4j.LogManager
import java.security.KeyPair
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

class RSAKeyPairGenerator(keyLen: Int) : KeyPairGenerator {
    private val keyLen: Int

    init {
        if (keyLen != 1024 && keyLen != 2048) {
            log.debug("keyLen 값: {}", keyLen)
            throw WrongKeyLengthException()
        }

        if (keyLen == 1024) {
            log.info("key 길이는 2048bit 이상을 권장합니다.")
        }

        this.keyLen = keyLen
    }

    override fun generateKeyPair(): KeyPair {
        return try {
            val keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(keyLen, SecureRandom())
            keyPairGenerator.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e)
        }
    }

    companion object {
        private val log = LogManager.getLogger()
        private const val NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE = ("NoSuchAlgorithmException: "
                + "\n지원하지 않는 암호화 알고리즘 입니다.")
    }
}
