package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
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
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.AESGCM
    }

    @Throws(CryptoFailException::class)
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
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(getMessage("exception.invalidAlgorithmParameter"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(getMessage("exception.aes.invalidKey"), e)
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
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }
            cipher.doFinal(encryptedData)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw CryptoFailException(getMessage("exception.invalidAlgorithmParameter"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(getMessage("exception.aes.invalidKey"), e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(getMessage("exception.noSuchPadding"), e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    /**
     * 추가 인증 데이터를 업데이트 합니다.
     *
     * @param aad 추가 인증 데이터
     */
    fun updateAAD(aad: String) {
        this.aad = aad
    }

    override fun generateSpec(): GCMParameterSpec {
        return GCMParameterSpec(GCM_TAG_LENGTH * 8, generate(GCM_IV_LENGTH))
    }

    companion object {
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
