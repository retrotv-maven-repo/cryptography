package dev.retrotv.crypto.twe.algorithm.stream

import dev.retrotv.crypto.twe.algorithm.StreamCipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.RC4Engine
import org.bouncycastle.crypto.params.KeyParameter

@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class RC4 : StreamCipherAlgorithm() {

    init {
        this.engine = RC4Engine()
        this.algorithm = Algorithm.Cipher.RC4
    }

    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return encryptedData
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        val params = KeyParameter(key)
        this.engine.init(true, params)

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return originalData
    }
}