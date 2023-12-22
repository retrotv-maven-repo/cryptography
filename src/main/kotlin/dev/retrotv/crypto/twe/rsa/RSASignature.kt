package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.DigitalSignature
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import java.security.*

class RSASignature : DigitalSignature {
    private val algorithm: Algorithm.Signature

    constructor() {
        algorithm = Algorithm.Signature.SHA1
    }

    constructor(algorithm: Algorithm.Signature) {
        this.algorithm = algorithm
    }

    @Throws(CryptoFailException::class)
    override fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray {
        return try {
            val signature = Signature.getInstance(algorithm.label())
            signature.initSign(privateKey)
            signature.update(data)
            signature.sign()
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e)
        } catch (e: SignatureException) {
            throw CryptoFailException(SIGNATURE_EXCEPTION_MESSAGE, e)
        }
    }

    @Throws(CryptoFailException::class)
    override fun verify(originalData: ByteArray, encryptedData: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val signature = Signature.getInstance(algorithm.label())
            signature.initVerify(publicKey)
            signature.update(originalData)
            signature.verify(encryptedData)
        } catch (e: NoSuchAlgorithmException) {
            throw CryptoFailException(getMessage("exception.noSuchAlgorithm"), e)
        } catch (e: InvalidKeyException) {
            throw CryptoFailException(INVALID_KEY_EXCEPTION_MESSAGE, e)
        } catch (e: SignatureException) {
            throw CryptoFailException(SIGNATURE_EXCEPTION_MESSAGE, e)
        }
    }

    companion object {
        private val log = LogManager.getLogger()
        private const val INVALID_KEY_EXCEPTION_MESSAGE = "암호화 키는 DES의 경우 8byte, Triple DES의 경우 24byte 길이의 키만 사용할 수 있습니다."
        private const val SIGNATURE_EXCEPTION_MESSAGE = "서명이 유효하지 않습니다."
    }
}
