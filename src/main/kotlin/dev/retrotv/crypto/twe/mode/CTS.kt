package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.param.Params
import dev.retrotv.crypto.twe.param.ParamsWithIV
import dev.retrotv.crypto.twe.result.Result
import dev.retrotv.enums.Mode.CTS
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.modes.CTSBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CTS(blockCipherAlgorithm: BlockCipherAlgorithm) : CipherMode(CTS, blockCipherAlgorithm) {

    override fun encrypt(data: ByteArray, params: Params): Result {
        params as ParamsWithIV
        val cipher = CTSBlockCipher(this.engine)
            cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
        val len = cipher.processBytes(data, 0, data.size, encryptedData, 0)
            cipher.doFinal(encryptedData, len)

        return Result(encryptedData)
    }

    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        params as ParamsWithIV
        val cipher = CTSBlockCipher(this.engine)
            cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
        val len = cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)
            cipher.doFinal(originalData, len)

        return Result(originalData)
    }

    fun useCBCMode() {
        this.engine = CBCBlockCipher.newInstance(this.engine)
    }
}