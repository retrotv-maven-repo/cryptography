package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.enums.Padding
import org.apache.logging.log4j.LogManager
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

/**
 * RSA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class RSACipher : TwoWayEncryption {
    private val algorithm: CipherAlgorithm = CipherAlgorithm.RSA
    private var padding = Padding.OAEP_WITH_SHA1_MGF1_PADDING

    override fun encrypt(data: ByteArray, publicKey: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return encrypt(data, publicKey)
    }

    fun encrypt(data: ByteArray, publicKey: Key): ByteArray {
        val algorithmName = algorithm.label() + "/" + padding.label()
        if (padding == Padding.PKCS1_PADDING) {
            log.debug("PKCS#1 Padding 기법은 오라클 패딩 공격에 취약합니다.\n호환성이 목적이 아니라면 보안을 위해, 패딩 방식 변경을 고려하십시오.")
        }
        return try {
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            cipher.doFinal(data)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.")
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.")
        } catch (e: BadPaddingException) {
            throw CryptoFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.")
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.")
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e)
        }
    }

    override fun decrypt(encryptedData: ByteArray, privateKey: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return decrypt(encryptedData, privateKey)
    }

    fun decrypt(encryptedData: ByteArray, privateKey: Key): ByteArray {
        val algorithmName = algorithm.label() + "/" + padding.label()
        log.debug("선택된 알고리즘: {}", algorithmName)
        return try {
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher.doFinal(encryptedData)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException("InvalidKeyException: \n유효하지 않은 키 입니다.\nRSA 암호화 방식에서 지원하는 키 길이인지 확인하십시오.")
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException("IllegalBlockSizeException: \n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.")
        } catch (e: BadPaddingException) {
            throw CryptoFailException("BadPaddingException: \n암호화 시 사용한 키와 일치하지 않습니다.")
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException("NoSuchPaddingException: \n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.")
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e)
        }
    }

    fun dataPadding(padding: Padding) {
        this.padding = padding
    }

    companion object {
        private val log = LogManager.getLogger()
        private const val NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE = ("NoSuchAlgorithmException: "
                + "\n지원하지 않는 암호화 알고리즘 입니다.")
    }
}