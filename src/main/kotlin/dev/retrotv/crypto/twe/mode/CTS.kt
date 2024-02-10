package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.twe.*
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.modes.CTSBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class CTS(cipherAlgorithm: CipherAlgorithm) : BCTwoWayEncryption {
    private var engine = cipherAlgorithm.engine
    private val algorithm = cipherAlgorithm.algorithm
    private val ivLen = when (cipherAlgorithm.algorithm) {
        Algorithm.Cipher.AES, Algorithm.Cipher.ARIA, Algorithm.Cipher.LEA -> 16
        Algorithm.Cipher.DES, Algorithm.Cipher.TRIPLE_DES -> 8
        else -> throw IllegalArgumentException("사용할 수 없는 알고리즘 입니다.")
    }

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