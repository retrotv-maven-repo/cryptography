package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.KeyGenerator
import dev.retrotv.crypto.twe.TwoWayEncryption
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.enums.Padding
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

val log: Logger = LogManager.getLogger()
const val BAD_PADDING_EXCEPTION_MESSAGE = (
        "BadPaddingException: "
        + "\n암호화 시 사용한 키와 일치하지 않습니다.")

const val ILLEGAL_BLOCK_SIZE_EXCEPTION_MESSAGE = (
        "IllegalBlockSizeException: "
        + "\n암호화 되지 않은 데이터의 복호화를 시도중 이거나, 이미 다른 유형으로 인코딩 된 데이터의 암복호화를 시도하는 중인지 확인하십시오.")

const val INVALID_ALGORITHM_PARAMETER_EXCEPTION_MESSAGE = (
        "InvalidAlgorithmParameterException: "
        + "\n%JAVA_HOME%\\jre\\lib\\security\\cacerts 파일이 존재하지 않거나 내부에 데이터가 존재하지 않는지 확인하십시오.")

const val INVALID_KEY_EXCEPTION_MESSAGE = (
        "InvalidKeyException: "
        + "\n1. 암호화 키는 각각 16/24/32 byte 길이의 키만 사용할 수 있습니다."
        + "\n2. JDK 8u161 이전 버전 및 Oracle JDK를 사용하는 경우, 16 byte 이상의 키 사용이 제한될 수 있습니다."
        + "\n   이에 대해서는 InvalidKeyException 무제한 강도 정책(Unlimited Strength Jurisdiction Policy)을 참조하십시오.")

const val NO_SUCH_PADDING_EXCEPTION_MESSAGE = (
        "NoSuchPaddingException: "
        + "\n지원되지 않거나, 부정확한 포맷으로 패딩된 데이터를 암복호화 시도하고 있습니다.")

const val NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE = (
        "NoSuchAlgorithmException: "
        + "\n지원하지 않는 암호화 알고리즘 입니다.")

abstract class DES : TwoWayEncryption, KeyGenerator {
    protected var algorithm: CipherAlgorithm? = null
    protected var padding = Padding.NO_PADDING

    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        if (algorithm == CipherAlgorithm.DESECB || algorithm == CipherAlgorithm.TRIPLE_DESECB) {
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
            if (algorithm == CipherAlgorithm.DESECB || algorithm == CipherAlgorithm.TRIPLE_DESECB) {
                cipher.init(Cipher.ENCRYPT_MODE, key)
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, spec)
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
            log.debug("선택된 알고리즘: {}", algorithmName)
            val cipher = Cipher.getInstance(algorithmName)
            if (algorithm == CipherAlgorithm.DESECB || algorithm == CipherAlgorithm.TRIPLE_DESECB) {
                cipher.init(Cipher.DECRYPT_MODE, key)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, spec)
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

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    fun dataPadding() {
        padding = Padding.PKCS5_PADDING
    }
}
