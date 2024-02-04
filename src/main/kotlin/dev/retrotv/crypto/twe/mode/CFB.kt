package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.modes.CFBBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import javax.crypto.spec.IvParameterSpec

class CFB(private val engine: BlockCipher) : BCTwoWayEncryption, ParameterSpecGenerator<IvParameterSpec> {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CBC 모드는 ParamsWithIV 객체를 요구합니다." }

        // blockSize는 8 혹은 16만 입력 가능
        val cipher = CFBBlockCipher.newInstance(this.engine, 128)
        cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
        cipher.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "CBC 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = CFBBlockCipher.newInstance(this.engine, 128)
        cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
        cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(16))
    }
}