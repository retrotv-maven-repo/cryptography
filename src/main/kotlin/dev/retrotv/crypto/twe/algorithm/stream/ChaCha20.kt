package dev.retrotv.crypto.twe.algorithm.stream

import dev.retrotv.crypto.twe.algorithm.StreamCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.engines.RC4Engine
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.InputStream
import java.io.OutputStream

class ChaCha20 : StreamCipherAlgorithm() {

    init {
        this.engine = ChaChaEngine(20)
        this.algorithm = Algorithm.Cipher.CHACHA20
    }

    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val params = ParametersWithIV(KeyParameter(key), iv)
        this.engine.init(true, params)

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return encryptedData
    }

    fun encrypt(input: InputStream, output: OutputStream, key: ByteArray, iv: ByteArray) {
        val params = ParametersWithIV(KeyParameter(key), iv)
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

    fun decrypt(encryptedData: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val params = ParametersWithIV(KeyParameter(key), iv)
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }

    fun decrypt(input: InputStream, output: OutputStream, key: ByteArray, iv: ByteArray) {
        val params = ParametersWithIV(KeyParameter(key), iv)
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