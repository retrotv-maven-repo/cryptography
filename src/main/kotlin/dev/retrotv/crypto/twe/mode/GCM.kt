package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

class GCM(cipherAlgorithm: CipherAlgorithm) : BCTwoWayEncryption, IVGenerator {
    private val engine = cipherAlgorithm.engine
    private val algorithm = cipherAlgorithm.algorithm
    private var aad: ByteArray? = null

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val macSize = GCM_TAG_LENGTH * 8
        val cipher = GCMBlockCipher.newInstance(this.engine)
            cipher.init(true, AEADParameters(KeyParameter(params.key), macSize, params.iv, aad))

        val outputData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, outputData, 0)

        try {
            tam += cipher.doFinal(outputData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("GCM 인증 태그를 생성 실패: " + e.message, e)
        }

        val encryptedData = ByteArray(tam - (macSize / 8))
        val authTag = ByteArray(macSize / 8)

        System.arraycopy(outputData, 0, encryptedData, 0, encryptedData.size)
        System.arraycopy(outputData, tam - (macSize / 8), authTag, 0, macSize / 8)

        return AEADResult(encryptedData, authTag)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val macSize = GCM_TAG_LENGTH * 8
        val cipher = GCMBlockCipher.newInstance(this.engine)
            cipher.init(false, AEADParameters(KeyParameter(params.key), macSize, params.iv, aad))

        val originalData = ByteArray(cipher.getOutputSize(encryptedData.size))
        var tam = cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        try {
            tam += cipher.doFinal(originalData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("GCM 인증 태그를 생성 실패: " + e.message, e)
        }

        return AEADResult(originalData, cipher.mac)
    }

    override fun generateIV(): ByteArray {
        return generate(GCM_IV_LENGTH)
    }

    /**
     * 추가 인증 데이터를 업데이트 합니다.
     *
     * @param aad 추가 인증 데이터
     */
    fun updateAAD(aad: ByteArray) {
        this.aad = aad
    }

    companion object {
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}