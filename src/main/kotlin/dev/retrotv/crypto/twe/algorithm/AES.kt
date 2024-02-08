package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.engines.AESEngine

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
        this.engine = AESEngine.newInstance()
        this.algorithm = Algorithm.Cipher.AES
    }

    override fun generateKey(): ByteArray {
        return generate(keyLen / 8)
    }
}
