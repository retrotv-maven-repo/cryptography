package dev.retrotv.crypto.twe.algorithm.stream

import dev.retrotv.crypto.twe.algorithm.StreamCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.engines.RC4Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

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

    fun decrypt(encryptedData: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val params = ParametersWithIV(KeyParameter(key), iv)
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }
}