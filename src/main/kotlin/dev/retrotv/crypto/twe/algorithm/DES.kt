package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.generators.DESKeyGenerator
import java.security.SecureRandom

/**
 * DES 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class DES : BlockCipherAlgorithm() {

    init {
        this.engine = DESEngine()
        this.algorithm = Algorithm.Cipher.DES
    }

    fun generateKey(): ByteArray {
        val keyGenerationParam = KeyGenerationParameters(SecureRandom(), 0)
        val keyGenerator = DESKeyGenerator()
            keyGenerator.init(keyGenerationParam)

        return keyGenerator.generateKey()
    }
}
