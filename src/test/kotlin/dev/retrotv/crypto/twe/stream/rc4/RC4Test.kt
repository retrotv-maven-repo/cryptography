package dev.retrotv.crypto.twe.stream.rc4

import dev.retrotv.crypto.twe.algorithm.stream.RC4
import dev.retrotv.data.utils.ByteUtils
import org.junit.jupiter.api.DisplayName
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals

class RC4Test {

    @Test
    @DisplayName("RC4 암호화 테스트")
    fun test_RC4() {
        val message = "The lazy dog jumps over the brown fox!".toByteArray()
        val key = "0123456789012345".toByteArray()

        val rc4 = RC4()
        var encryptedData = rc4.encrypt(message, key)
        println(ByteUtils.toHexString(encryptedData))

        val originalData = rc4.decrypt(encryptedData, key)
        println(String(originalData))

        val inputStream = message.inputStream()
        val outputStream = ByteArrayOutputStream()
        rc4.encrypt(inputStream, outputStream, key)

        encryptedData = outputStream.toByteArray()
        println(ByteUtils.toHexString(encryptedData))

        outputStream.reset()
        rc4.decrypt(encryptedData.inputStream(), outputStream, key)
        assertEquals(String(outputStream.toByteArray()), String(originalData))
    }
}