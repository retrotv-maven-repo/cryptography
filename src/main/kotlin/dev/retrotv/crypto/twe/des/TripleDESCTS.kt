package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

/**
 * TripleDES/CTS 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class TripleDESCTS : TripleDES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        algorithm = Algorithm.Cipher.TRIPLE_DESCTS
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(8))
    }
}
