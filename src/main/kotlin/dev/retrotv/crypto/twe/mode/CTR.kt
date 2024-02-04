package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CTR(cipherAlgorithm: CipherAlgorithm) : BCTwoWayEncryption, IVGenerator {
    private val engine = cipherAlgorithm.engine
    private val algorithm = cipherAlgorithm.algorithm

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val cipher = SICBlockCipher.newInstance(this.engine)
        cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
        cipher.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        params as ParamsWithIV

        val cipher = SICBlockCipher.newInstance(this.engine)
        cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
        cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

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