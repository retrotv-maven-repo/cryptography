package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.spec.GCMParameterSpec

/**
 * LEA/GCM 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEAGCM(keyLen: Int) : LEA(), ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: ByteArray? = null

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.LEAGCM
    }

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val macSize = 128
        val cipher = GCMBlockCipher.newInstance(this.engine)
            cipher.init(true, AEADParameters(KeyParameter(params.key), macSize, params.iv, aad))

        if (aad != null) {
            cipher.processAADBytes(aad, 0, aad?.size ?: 0)
        }

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

        val macSize = 128
        val cipher = GCMBlockCipher.newInstance(this.engine)
            cipher.init(false, AEADParameters(KeyParameter(params.key), macSize, params.iv, aad))

        if (aad != null) {
            cipher.processAADBytes(aad, 0, aad?.size ?: 0)
        }

        val originalData = ByteArray(cipher.getOutputSize(encryptedData.size))
        var tam = cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        try {
            tam += cipher.doFinal(originalData, tam)
        } catch (e: InvalidCipherTextException) {
            throw CryptoFailException("GCM 인증 태그를 생성 실패: " + e.message, e)
        }

        return AEADResult(originalData, cipher.mac)
    }

    override fun generateSpec(): GCMParameterSpec {
        return GCMParameterSpec(GCM_TAG_LENGTH * 8, generate(GCM_IV_LENGTH))
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
