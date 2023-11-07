package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

/**
 * TripleDES/CTR 양방향 암호화 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class TripleDESCTR : DES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        algorithm = CipherAlgorithm.TRIPLE_DESCTR
    }

    override fun generateKey(): Key {
        return try {
            val keyGenerator = KeyGenerator.getInstance("DESede")
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.")
        }
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(SecureRandomUtil.generate(8))
    }
}
