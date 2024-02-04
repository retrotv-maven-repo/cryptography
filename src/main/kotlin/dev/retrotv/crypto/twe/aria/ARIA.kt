package dev.retrotv.crypto.twe.aria

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.BCKeyGenerator
import dev.retrotv.crypto.twe.BCTwoWayEncryption
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.Result
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.engines.ARIAEngine
import java.security.Key

/**
 * ARIA 알고리즘 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class ARIA(keyLen: Int) : BCKeyGenerator {
    val engine = ARIAEngine()
    private var keyLen: Int
    private var algorithm: Algorithm.Cipher

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        this.algorithm = Algorithm.Cipher.ARIA
    }

    override fun generateKey(): ByteArray {
        return generate(keyLen / 8)
    }
}