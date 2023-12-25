package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import javax.crypto.spec.IvParameterSpec

/**
 * TripleDES/CBC 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class TripleDESCBC : TripleDES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        algorithm = Algorithm.Cipher.TRIPLE_DESCBC
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(8))
    }
}
