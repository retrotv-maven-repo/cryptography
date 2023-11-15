package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.generate
import javax.crypto.spec.IvParameterSpec

/**
 * AES/OFB 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class AESOFB(keyLen: Int) : AES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw WrongKeyLengthException()
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.AESOFB
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(16))
    }
}
