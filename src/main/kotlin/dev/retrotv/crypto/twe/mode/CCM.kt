package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.spec.GCMParameterSpec

class CCM(private val engine: BlockCipher) : BCTwoWayEncryption, ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: ByteArray? = null

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val macSize = 128
        val cipher = CCMBlockCipher.newInstance(this.engine)
        cipher.init(true, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)

        // doFinal을 해야 tag까지 정상적으로 생성된다
        tam += cipher.doFinal(encryptedData, tam)

        return AEADResult(encryptedData, cipher.mac)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val macSize = 128
        val cipher = CCMBlockCipher.newInstance(this.engine)
        cipher.init(false, AEADParameters(KeyParameter(params.key), macSize, params.iv, this.aad))

        val originalData = ByteArray(cipher.getOutputSize(encryptedData.size))
        var tam = cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)
        tam += cipher.doFinal(originalData, tam)

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