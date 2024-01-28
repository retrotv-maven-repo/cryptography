package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.spec.GCMParameterSpec

/**
 * LEA/CCM 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEACCM(keyLen: Int) : LEA(), ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: ByteArray? = null

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.LEACCM
    }

    fun encrypt(data: ByteArray, params: Params): ByteArray {
        params as ParamsWithIV

        val macSize = 128
        val cipher = CCMBlockCipher.newInstance(LEAEngine())
            cipher.init(true, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val outputData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, outputData, 0)

            // doFinal을 해야 tag까지 정상적으로 생성된다
            tam += cipher.doFinal(outputData, tam)

        return outputData
    }

    fun decrypt(encryptedData: ByteArray, params: Params): ByteArray {
        params as ParamsWithIV

        val macSize = 128
        val cipher = CCMBlockCipher.newInstance(LEAEngine())
            cipher.init(false, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val result = ByteArray(cipher.getOutputSize(encryptedData.size))
        var tam = cipher.processBytes(encryptedData, 0, encryptedData.size, result, 0)
            tam += cipher.doFinal(result, tam)

        return result
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
