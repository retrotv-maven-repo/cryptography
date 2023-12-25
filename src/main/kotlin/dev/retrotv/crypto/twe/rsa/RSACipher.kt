package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.getMessage
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
    private val algorithm = Algorithm.Cipher.RSA
    private var padding = Padding.OAEP_WITH_SHA1_MGF1_PADDING

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, publicKey: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return encrypt(data, publicKey)
    }

    @Throws(CryptoFailException::class)
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
            throw CryptoFailException(getMessage("exception.public.invalidKey"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, privateKey: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return decrypt(encryptedData, privateKey)
    }

    @Throws(CryptoFailException::class)
    fun decrypt(encryptedData: ByteArray, privateKey: Key): ByteArray {
        val algorithmName = algorithm.label() + "/" + padding.label()
        log.debug("선택된 알고리즘: {}", algorithmName)
        return try {
            val cipher = Cipher.getInstance(algorithmName)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            cipher.doFinal(encryptedData)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(getMessage("exception.private.invalidKey"), e)
        } catch (e: IllegalBlockSizeException) {
            throw CryptoFailException(getMessage("exception.illegalBlockSize"), e)
        } catch (e: BadPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: NoSuchPaddingException) {
            throw CryptoFailException(getMessage("exception.badPadding"), e)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }

    fun dataPadding(padding: Padding) {
        this.padding = padding
    }

    companion object {
        private val log = LogManager.getLogger()
    }
}