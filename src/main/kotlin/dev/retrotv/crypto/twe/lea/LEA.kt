package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.KeyGenerator
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.generate
import kr.re.nsr.crypto.BlockCipher
import kr.re.nsr.crypto.BlockCipherMode
import kr.re.nsr.crypto.padding.PKCS5Padding
import kr.re.nsr.crypto.symm.LEA.*
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

val log: Logger = LogManager.getLogger()

/**
 * LEA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
abstract class LEA : TwoWayEncryption, KeyGenerator {
    protected var keyLen = 0
    protected var algorithm: Algorithm.Cipher? = null
    protected var padding = Padding.NO_PADDING

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        log.debug("선택된 알고리즘: {}", algorithm?.label() + "/" + padding.label())
        if (algorithm == Algorithm.Cipher.LEAECB && data.size > keyLen) {
            log.debug("ECB 블록암호 운영모드는 대용량 데이터를 처리하는데 적합하지 않습니다.")
        }

        if (padding == Padding.PKCS5_PADDING) {
            log.debug("PKCS#5 Padding 기법은 오라클 패딩 공격에 취약합니다.")
            log.debug("호환성이 목적이 아니라면, 보안을 위해 패딩이 불필요한 블록 암호화 운영모드 사용을 고려하십시오.")
        }

        return try {
            val cipher: BlockCipherMode = getCipherMode(algorithm)
            val ivSpec: IvParameterSpec? = spec as IvParameterSpec?

            if (algorithm == Algorithm.Cipher.LEAECB) {
                cipher.init(BlockCipher.Mode.ENCRYPT, key.encoded)
            } else {
                checkNotNull(ivSpec)
                cipher.init(BlockCipher.Mode.ENCRYPT, key.encoded, ivSpec.iv)
            }

            if (padding == Padding.PKCS5_PADDING) {
                cipher.setPadding(PKCS5Padding(16))
            }

            cipher.doFinal(data)
        } catch (e: Exception) {
            throw CryptoFailException(e.message!!, e)
        }
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        log.debug("선택된 알고리즘: {}", algorithm?.label() + "/" + padding.label())
        return try {
            val cipher: BlockCipherMode = getCipherMode(algorithm)
            val ivSpec: IvParameterSpec? = spec as IvParameterSpec?

            if (algorithm == Algorithm.Cipher.LEAECB) {
                cipher.init(BlockCipher.Mode.DECRYPT, key.encoded)
            } else {
                checkNotNull(ivSpec)
                cipher.init(BlockCipher.Mode.DECRYPT, key.encoded, ivSpec.iv)
            }

            if (padding == Padding.PKCS5_PADDING) {
                cipher.setPadding(PKCS5Padding(16))
            }

            cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            throw CryptoFailException(e.message!!, e)
        }
    }

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    fun dataPadding() {
        padding = Padding.PKCS5_PADDING
    }

    override fun generateKey(): Key {
        return SecretKeySpec(generate(keyLen / 8), "LEA")
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun getCipherMode(algorithm: Algorithm.Cipher?): BlockCipherMode {
        val cipher: BlockCipherMode = when (algorithm) {
            Algorithm.Cipher.LEACBC -> CBC()
            Algorithm.Cipher.LEACFB -> CFB()
            Algorithm.Cipher.LEACTR -> CTR()
            Algorithm.Cipher.LEAECB -> ECB()
            Algorithm.Cipher.LEAOFB -> OFB()
            else -> throw NoSuchAlgorithmException("지원하지 않는 알고리즘 입니다.")
        }

        return cipher
    }
}
