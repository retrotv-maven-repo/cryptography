package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.BCKeyGenerator
import dev.retrotv.crypto.twe.BCTwoWayEncryption
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.Result
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.bouncycastle.crypto.engines.LEAEngine
import java.security.Key

/**
 * LEA 알고리즘 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class LEA(keyLen: Int) : BCKeyGenerator {
    val engine = LEAEngine()
    private var keyLen: Int
    private var algorithm: Algorithm.Cipher

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        this.algorithm = Algorithm.Cipher.LEA
    }

    override fun generateKey(): ByteArray {
        return generate(keyLen / 8)
    }
}
