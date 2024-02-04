package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CBC(cipherAlgorithm: CipherAlgorithm) : BCTwoWayEncryption, IVGenerator {
    private val engine = cipherAlgorithm.engine
    private val algorithm = cipherAlgorithm.algorithm

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

    override fun generateIV(): ByteArray {
        return if (this.algorithm === Algorithm.Cipher.DES || this.algorithm === Algorithm.Cipher.TRIPLE_DES) {
            generate(8)
        } else {
            generate(16)
        }
    }
}