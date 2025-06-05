package dev.retrotv.crypto.cipher.block.mode

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.cipher.block.CipherMode
import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.crypto.cipher.result.AEADResult
import dev.retrotv.crypto.cipher.result.Result
import dev.retrotv.crypto.enums.EMode.ECB
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * GCM 암호화 모드 클래스 입니다.
 * @param blockCipher 블록 암호화 클래스
 */
class GCM(blockCipher: BlockCipher) : CipherMode(ECB, blockCipher) {
    private var aad: ByteArray? = null

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Param): Result {
        require (params is ParamWithIV) { "GCM 모드는 ParamsWithIV 객체를 요구합니다." }

        val macSize = tLen * 8
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

    @SuppressWarnings("kotlin:S6615")
    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Param): Result {
        require (params is ParamWithIV) { "GCM 모드는 ParamsWithIV 객체를 요구합니다." }

        val macSize = tLen * 8
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

    fun updateTagLength(tagLength: Int) {
        require(tagLength in 12..16) { "인증태그의 길이는 12 ~ 16Byte만 허용됩니다." }
        tLen = tagLength
    }

    companion object {
        private const val DEFAULT_TAG_LENGTH = 16
        private var tLen = DEFAULT_TAG_LENGTH
    }
}