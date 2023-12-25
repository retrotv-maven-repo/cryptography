package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.DigitalSignature
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.getMessage
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
            throw CryptoFailException(getMessage("exception.private.invalidKey"), e)
        } catch (e: SignatureException) {
            throw CryptoFailException(getMessage("exception.signature"), e)
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
            throw CryptoFailException(getMessage("exception.public.invalidKey"), e)
        } catch (e: SignatureException) {
            throw CryptoFailException(getMessage("exception.signature"), e)
        }
    }
}
