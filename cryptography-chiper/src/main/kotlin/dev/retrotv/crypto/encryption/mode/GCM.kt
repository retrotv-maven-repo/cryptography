package dev.retrotv.crypto.encryption.mode

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.param.ParamsWithIV
import dev.retrotv.crypto.encryption.result.AEADResult
import dev.retrotv.crypto.encryption.result.Result
import dev.retrotv.crypto.enums.EMode.ECB
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

class GCM(blockCipher: BlockCipher) : CipherMode(ECB, blockCipher) {
    private var aad: ByteArray? = null

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "GCM 모드는 ParamsWithIV 객체를 요구합니다." }

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

        val encryptedData = ByteArray(tam)

        System.arraycopy(outputData, 0, encryptedData, 0, encryptedData.size)

        return AEADResult(encryptedData, cipher.mac)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "GCM 모드는 ParamsWithIV 객체를 요구합니다." }

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