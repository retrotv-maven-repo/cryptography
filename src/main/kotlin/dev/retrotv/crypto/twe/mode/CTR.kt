package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.param.Params
import dev.retrotv.crypto.twe.param.ParamsWithIV
import dev.retrotv.crypto.twe.result.Result
import dev.retrotv.enums.Mode.CTS
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CTR(blockCipherAlgorithm: BlockCipherAlgorithm) : CipherMode(CTS, blockCipherAlgorithm) {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CTR 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = SICBlockCipher.newInstance(this.engine)
            cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
            cipher.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CTR 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = SICBlockCipher.newInstance(this.engine)
            cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
            cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }
}