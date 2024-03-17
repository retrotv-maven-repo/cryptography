package dev.retrotv.crypto.twe.stream.chacha20

import dev.retrotv.crypto.twe.algorithm.stream.ChaCha20
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.DisplayName
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test

class ChaCha20Test {

    @Test
    @DisplayName("ChaCha20 암호화 테스트")
    fun test_ChaCha20() {
        var messageString = "The lazy dog jumps over the brown fox!"
        for (i: Int in 1..6) {
            messageString += messageString
        }
        val message = messageString.toByteArray()

        val key = "01234567890123450123456789012345".toByteArray()
        val iv = "01234567".toByteArray()

        println(message.size)

        val chacha20 = ChaCha20()
        var encryptedData = chacha20.encrypt(message, key, iv)
        println(toHexString(encryptedData))

        val originalData = chacha20.decrypt(encryptedData, key, iv)
        println(String(originalData))

        var bais = ByteArrayInputStream(message)
        var baos = ByteArrayOutputStream()
        chacha20.encrypt(bais, baos, key, iv)

        encryptedData = baos.toByteArray()

        println(toHexString(encryptedData))

        bais = ByteArrayInputStream(encryptedData)
        baos = ByteArrayOutputStream()
        chacha20.decrypt(bais, baos, key, iv)

        println(String(baos.toByteArray()))

        bais = ByteArrayInputStream(message)
        baos = ByteArrayOutputStream()
        chacha20.encrypt(bais, baos, ParametersWithIV(KeyParameter(key), iv))

        encryptedData = baos.toByteArray()

        println(toHexString(encryptedData))

        bais = ByteArrayInputStream(encryptedData)
        baos = ByteArrayOutputStream()
        chacha20.decrypt(bais, baos, ParametersWithIV(KeyParameter(key), iv))

        println(String(baos.toByteArray()))
    }
}