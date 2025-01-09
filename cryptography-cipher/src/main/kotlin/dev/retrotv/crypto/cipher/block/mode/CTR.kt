package dev.retrotv.crypto.cipher.block.mode

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.cipher.block.CipherMode
import dev.retrotv.crypto.cipher.param.Params
import dev.retrotv.crypto.cipher.param.ParamsWithIV
import dev.retrotv.crypto.cipher.result.Result
import dev.retrotv.crypto.enums.EMode.CTS
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * CTR 암호화 모드 클래스 입니다.
 * @param blockCipher 블록 암호화 클래스
 */
class CTR(blockCipher: BlockCipher) : CipherMode(CTS, blockCipher) {

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