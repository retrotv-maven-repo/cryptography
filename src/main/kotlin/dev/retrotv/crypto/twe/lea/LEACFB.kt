package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.generate
import javax.crypto.spec.IvParameterSpec

/**
 * LEA/CFB 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEACFB(keyLen: Int) : LEA(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            "해당 알고리즘이 지원하지 않는 키 길이 입니다."
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.LEACFB
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(16))
    }
}
