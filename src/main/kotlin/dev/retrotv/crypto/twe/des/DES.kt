package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.twe.KeyGenerator
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

/**
 * DES 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
abstract class DES : TwoWayEncryption, KeyGenerator {
    protected val log: Logger = LogManager.getLogger(this.javaClass)

    protected var algorithm: Algorithm.Cipher? = null
    protected var padding = Padding.NO_PADDING

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        if (algorithm == Algorithm.Cipher.DESECB || algorithm == Algorithm.Cipher.TRIPLE_DESECB) {
            log.debug("ECB 블록암호 운영모드는 대용량 데이터를 처리하는데 적합하지 않습니다.")
        }

        if (padding == Padding.PKCS5_PADDING) {
            log.debug("PKCS#5 Padding 기법은 오라클 패딩 공격에 취약합니다.")
            log.debug("호환성이 목적이 아니라면, 보안을 위해 패딩이 불필요한 블록 암호화 운영모드 사용을 고려하십시오.")
        }

        val algorithmName = algorithm!!.label() + "/" + padding.label()
        return try {
            log.debug("선택된 알고리즘: {}", algorithmName)
            val cipher = Cipher.getInstance(algorithmName)
            if (algorithm == Algorithm.Cipher.DESECB || algorithm == Algorithm.Cipher.TRIPLE_DESECB) {
                cipher.init(Cipher.ENCRYPT_MODE, key)
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            }

            cipher.doFinal(data)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(getMessage("exception.invalidAlgorithmParameter"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(getMessage("exception.des.invalidKey"), e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(getMessage("exception.noSuchPadding"), e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        val algorithmName = algorithm!!.label() + "/" + padding.label()
        return try {
            log.debug("선택된 알고리즘: {}", algorithmName)
            val cipher = Cipher.getInstance(algorithmName)
            if (algorithm == Algorithm.Cipher.DESECB || algorithm == Algorithm.Cipher.TRIPLE_DESECB) {
                cipher.init(Cipher.DECRYPT_MODE, key)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, spec)
            }

            cipher.doFinal(encryptedData)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(getMessage("exception.invalidAlgorithmParameter"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(getMessage("exception.des.invalidKey"), e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(getMessage("exception.noSuchPadding"), e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    override fun generateKey(): Key {
        return try {
            val keyGenerator = javax.crypto.KeyGenerator.getInstance("DES")
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    fun dataPadding() {
        padding = Padding.PKCS5_PADDING
    }
}
