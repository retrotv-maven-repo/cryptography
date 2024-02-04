package dev.retrotv.crypto.twe.mode

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.BCTwoWayEncryption
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.Result
import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter

class ECB(private val engine: BlockCipher) : BCTwoWayEncryption {

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, params: Params): Result {
        val cipher = PaddedBufferedBlockCipher(this.engine)
        cipher.init(true, KeyParameter(params.key))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        val tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)
        cipher.doFinal(encryptedData, tam)

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