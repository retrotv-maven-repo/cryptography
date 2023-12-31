package dev.retrotv.crypto.twe.lea

import dev.retrotv.data.utils.binaryToHex
import dev.retrotv.data.utils.hexToBinary
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class LEACBCTest {
    @Test
    @DisplayName("LEACBC-128 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc128_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(128)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-192 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc192_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(192)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    @DisplayName("LEACBC-256 암복호화 테스트")
    @Throws(Exception::class)
    fun leacbc256_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val lea = LEACBC(256)
        val key = lea.generateKey()
        val iv = lea.generateSpec()
        lea.dataPadding()
        val encryptedData = lea.encrypt(message.toByteArray(), key, iv)
        val originalMessage = String(lea.decrypt(encryptedData, key, iv))
        Assertions.assertEquals(message, originalMessage)
    }

    @Test
    fun leacbc128() {
        val lea = LEACBC(128)

        val key = hexToBinary("00000000000000000000000000000000")
        val iv = hexToBinary("00000000000000000000000000000000")
        val data = hexToBinary("80000000000000000000000000000000")

        val encryptedData = lea.encrypt(data, SecretKeySpec(key, ""), IvParameterSpec(iv))
        println(binaryToHex(encryptedData))
    }

    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((s[i].digitToIntOrNull(16) ?: -1 shl 4)
            + s[i + 1].digitToIntOrNull(16)!! ?: -1).toByte()
            i += 2
        }
        return data
    }

    fun byteArrayToHexString(bytes: ByteArray): String {
        val sb = StringBuilder()

        for (b in bytes) {
            sb.append(String.format("%02X", b.toInt() and 0xff))
        }

        return sb.toString()
    }
}
