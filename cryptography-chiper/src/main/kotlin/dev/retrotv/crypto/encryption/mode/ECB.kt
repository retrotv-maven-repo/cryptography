package dev.retrotv.crypto.encryption.mode

import dev.retrotv.crypto.encryption.block.BlockCipher
import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.result.Result
import dev.retrotv.crypto.enums.EMode.ECB
import dev.retrotv.crypto.exception.CryptoFailException
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter

class ECB(blockCipher: BlockCipher) : CipherMode(ECB, blockCipher) {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        val cipher = PaddedBufferedBlockCipher(this.engine)
            cipher.init(true, KeyParameter(params.key))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        var tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)
            tam += cipher.doFinal(encryptedData, tam)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
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