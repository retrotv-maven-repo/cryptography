package dev.retrotv.crypto.twe

import dev.retrotv.crypto.twe.algorithm.stream.RC4
import dev.retrotv.data.utils.toHexString
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class RC4Test {

    @Test
    @DisplayName("RC4 암호화 테스트")
    fun test_RC4() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()
        val key = "0123456789012345".toByteArray()

        val rc4 = RC4()
        val encryptedData = rc4.encrypt(message, key)
        println(toHexString(encryptedData))

        val originalData = rc4.decrypt(encryptedData, key)
        println(String(originalData))
    }
}