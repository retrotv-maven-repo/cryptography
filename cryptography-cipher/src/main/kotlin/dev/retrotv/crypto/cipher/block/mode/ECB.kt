package dev.retrotv.crypto.cipher.block.mode

import dev.retrotv.crypto.cipher.block.BlockCipher
import dev.retrotv.crypto.cipher.block.CipherMode
import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.result.Result
import dev.retrotv.crypto.enums.EMode.ECB
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter

/**
 * ECB 암호화 모드 클래스 입니다.
 * @param blockCipher 블록 암호화 클래스
 */
class ECB(blockCipher: BlockCipher) : CipherMode(ECB, blockCipher) {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Param): Result {
        val cipher = PaddedBufferedBlockCipher(this.engine)
            cipher.init(true, KeyParameter(params.key))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)
            tam += cipher.doFinal(encryptedData, tam)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Param): Result {
        val cipher = PaddedBufferedBlockCipher(this.engine)
            cipher.init(false, KeyParameter(params.key))

        val outputData = ByteArray(cipher.getOutputSize(encryptedData.size))
        val tam = cipher.processBytes(encryptedData, 0, encryptedData.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val originalData = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, originalData, 0, tam + finalLen)

        return Result(originalData)
    }
}