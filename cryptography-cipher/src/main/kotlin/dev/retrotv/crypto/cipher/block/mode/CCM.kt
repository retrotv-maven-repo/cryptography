package dev.retrotv.crypto.cipher.block.mode

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.cipher.block.CipherMode
import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.crypto.cipher.result.AEADResult
import dev.retrotv.crypto.cipher.result.Result
import dev.retrotv.crypto.enums.EMode.CCM
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * CCM 암호화 모드 클래스 입니다.
 * @param blockCipher 블록 암호화 클래스
 */
class CCM(blockCipher: BlockCipher) : CipherMode(CCM, blockCipher) {
    private var aad: ByteArray? = null

    @SuppressWarnings("kotlin:S6615")
    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Param): Result {
        require (params is ParamWithIV) { "CCM 모드는 ParamsWithIV 객체를 요구합니다." }

        val macSize = tLen * 8
        val cipher = CCMBlockCipher.newInstance(this.engine)
            cipher.init(true, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)

        try {

            // doFinal을 해야 tag까지 정상적으로 생성된다
            tam += cipher.doFinal(encryptedData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("CCM 인증 태그 생성 실패: " + e.message, e)
        }

        return AEADResult(encryptedData, cipher.mac)
    }

    @SuppressWarnings("kotlin:S6615")
    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Param): Result {
        require (params is ParamWithIV) { "CCM 모드는 ParamsWithIV 객체를 요구합니다." }

        val macSize = tLen * 8
        val cipher = CCMBlockCipher.newInstance(this.engine)
            cipher.init(false, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val originalData = ByteArray(cipher.getOutputSize(encryptedData.size))
        var tam = cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        try {
            tam += cipher.doFinal(originalData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("CCM 인증 태그 생성 실패: " + e.message, e)
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

    /**
     * 인증 태그의 길이를 업데이트 합니다.
     *
     * @param tagLength 인증 태그의 길이 (2의 배수, 4 ~ 16 Byte)
     */
    fun updateTagLength(tagLength: Int) {
        require(tagLength % 2 == 0) { "인증태그의 길이는 2의 배수여야 합니다." }
        require(tagLength in 4..16) { "인증태그의 길이는 4 ~ 16Byte만 허용됩니다." }
        tLen = tagLength
    }

    companion object {
        private const val DEFAULT_TAG_LENGTH = 16
        private var tLen = DEFAULT_TAG_LENGTH
    }
}