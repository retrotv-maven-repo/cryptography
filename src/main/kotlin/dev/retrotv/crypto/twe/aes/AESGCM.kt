package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.GCMParameterSpec

/**
 * AES/GCM 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class AESGCM(keyLen: Int) : AES(), ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: String? = null

    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw WrongKeyLengthException()
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.AESGCM
    }

    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        val algorithmName = algorithm!!.label() + "/" + padding.label()
        return try {
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }
            cipher.doFinal(data)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(BAD_PADDING_EXCEPTION_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e)
        }
    }

    override fun decrypt(encryptedData: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        val algorithmName = algorithm!!.label() + "/" + padding.label()
        return try {
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }
            cipher.doFinal(encryptedData)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(BAD_PADDING_EXCEPTION_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE, e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(NO_SUCH_PADDING_EXCEPTION_MESSAGE, e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e)
        }
    }

    fun updateAAD(aad: String?) {
        this.aad = aad
    }

    override fun generateSpec(): GCMParameterSpec {
        return GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH))
    }

    companion object {
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
