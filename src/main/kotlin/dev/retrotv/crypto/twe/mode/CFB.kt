package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.param.Params
import dev.retrotv.crypto.twe.param.ParamsWithIV
import dev.retrotv.crypto.twe.result.Result
import dev.retrotv.enums.Algorithm.Cipher.*
import dev.retrotv.enums.Mode.CFB
import org.bouncycastle.crypto.engines.*
import org.bouncycastle.crypto.modes.CFBBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CFB(blockCipherAlgorithm: BlockCipherAlgorithm) : CipherMode(CFB, blockCipherAlgorithm) {
    private val blockSize by lazy {
        when (this.algorithm) {
            AES, ARIA, LEA, SEED -> 128
            DES, TRIPLE_DES -> 64
            else -> throw IllegalArgumentException("사용할 수 없는 알고리즘 입니다.")
        }
    }

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CFB 모드는 ParamsWithIV 객체를 요구합니다." }

        // blockSize는 8 혹은 16만 입력 가능
        val cipher = CFBBlockCipher.newInstance(this.engine, this.blockSize)
            cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
            cipher.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CFB 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = CFBBlockCipher.newInstance(this.engine, this.blockSize)
            cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
            cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }
}