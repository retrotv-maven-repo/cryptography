package dev.retrotv.crypto.twe.stream.chacha20

import dev.retrotv.crypto.twe.algorithm.stream.ChaCha20
import dev.retrotv.data.utils.toHexString
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class ChaCha20Test {

    @Test
    @DisplayName("ChaCha20 암호화 테스트")
    fun test_ChaCha20() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()
        val key = "01234567890123450123456789012345".toByteArray()
        val iv = "01234567".toByteArray()

        val chacha20 = ChaCha20()
        val encryptedData = chacha20.encrypt(message, key, iv)
        println(toHexString(encryptedData))

        val originalData = chacha20.decrypt(encryptedData, key, iv)
        println(String(originalData))
    }
}