package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.params.KeyParameter
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipherAlgorithm {
    lateinit var engine: StreamCipher
    lateinit var algorithm: Algorithm.Cipher

    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return encryptedData
    }

    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return encryptedData
    }

    fun encrypt(input: InputStream, output: OutputStream, key: ByteArray) {
        val data = input.read()
        data.toByte()
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }
}