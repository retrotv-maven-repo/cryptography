package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.*
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.modes.OFBBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

class OFB(cipherAlgorithm: CipherAlgorithm) : BCTwoWayEncryption {
    private val engine = cipherAlgorithm.engine
    private val algorithm = cipherAlgorithm.algorithm
    private val ivLen = when (cipherAlgorithm.algorithm) {
        Algorithm.Cipher.AES, Algorithm.Cipher.ARIA, Algorithm.Cipher.LEA -> 16
        Algorithm.Cipher.DES, Algorithm.Cipher.TRIPLE_DES -> 8
        else -> throw IllegalArgumentException("사용할 수 없는 알고리즘 입니다.")
    }
    private  val blockSize = when (cipherAlgorithm.algorithm) {
        Algorithm.Cipher.AES, Algorithm.Cipher.ARIA, Algorithm.Cipher.LEA -> 128
        Algorithm.Cipher.DES, Algorithm.Cipher.TRIPLE_DES -> 64
        else -> throw IllegalArgumentException("사용할 수 없는 알고리즘 입니다.")
    }

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "OFB 모드는 ParamsWithIV 객체를 요구합니다." }

        // blockSize는 8 혹은 16만 입력 가능 (16 권장)
        val cipher = OFBBlockCipher(this.engine, this.blockSize)
            cipher.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
            cipher.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require (params is ParamsWithIV) { "OFB 모드는 ParamsWithIV 객체를 요구합니다." }

        val cipher = OFBBlockCipher(this.engine, this.blockSize)
            cipher.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
            cipher.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }
}