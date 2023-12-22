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
 * DES/CBC 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class DESCBC : DES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        algorithm = Algorithm.Cipher.DESCBC
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(8))
    }
}
