package dev.retrotv.crypto.encryption.mode

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.param.ParamsWithIV
import dev.retrotv.crypto.encryption.result.Result
import dev.retrotv.crypto.enums.EMode.CBC
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CBC(blockCipher: BlockCipher) : CipherMode(CBC, blockCipher) {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CBC 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine))
            cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)
            tam += cipher.doFinal(encryptedData, tam)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CBC 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(this.engine))
            cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val outputData = ByteArray(cipher.getOutputSize(encryptedData.size))
        val tam = cipher.processBytes(encryptedData, 0, encryptedData.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val originalData = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, originalData, 0, tam + finalLen)

        return Result(originalData)
    }
}