package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.crypto.twe.KeyGenerator
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.bouncycastle.crypto.engines.ARIAEngine
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

/**
 * AES 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class AES(keyLen: Int) : CipherAlgorithm() {
    private var keyLen: Int

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        this.engine = ARIAEngine()
        this.algorithm = Algorithm.Cipher.ARIA
    }

    override fun generateKey(): ByteArray {
        return generate(keyLen / 8)
    }
}
