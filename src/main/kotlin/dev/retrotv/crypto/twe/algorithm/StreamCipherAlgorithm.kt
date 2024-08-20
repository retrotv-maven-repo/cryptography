package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipherAlgorithm {
    lateinit var engine: StreamCipher
    lateinit var algorithm: Algorithm.Cipher

    fun encrypt(data: ByteArray, params: CipherParameters): ByteArray {
        this.engine.init(true, params)

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return encryptedData
    }

    fun encrypt(input: InputStream, output: OutputStream, params: CipherParameters) {
        this.engine.init(true, params)

        val cos = CipherOutputStream(output, this.engine)
        val buffer = ByteArray(1024)
        var i: Int = input.read(buffer)
        while (i != -1) {
            cos.write(buffer, 0, i)
            i = input.read(buffer)
        }

        cos.flush()
        cos.close()
    }

    fun decrypt(encryptedData: ByteArray, params: CipherParameters): ByteArray {
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }

    fun decrypt(input: InputStream, output: OutputStream, params: CipherParameters) {
        this.engine.init(false, params)

        val cis = CipherInputStream(input, this.engine)
        val buffer = ByteArray(1024)
        var i: Int = cis.read(buffer)
        while (i != -1) {
            output.write(buffer, 0, i)
            i = cis.read(buffer)
        }

        cis.close()
    }
}