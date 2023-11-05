package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import javax.crypto.spec.IvParameterSpec

/**
 * AES/CBC 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class AESCBC(keyLen: Int) : AES(), ParameterSpecGenerator<IvParameterSpec?> {
    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw WrongKeyLengthException()
        }
        this.keyLen = keyLen
        algorithm = CipherAlgorithm.AESCBC
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(SecureRandomUtil.generate(16))
    }
}
