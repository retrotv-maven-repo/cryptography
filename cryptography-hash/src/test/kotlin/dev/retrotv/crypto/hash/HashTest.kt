package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.*
import dev.retrotv.crypto.util.CodecUtils
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.ByteUtils

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.RepeatedTest
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.IOException

class HashTest {
    private val password = "The quick brown fox jumps over the lazy dog"
    private val checksum = this.javaClass.getClassLoader().getResource("hash_code")
    private val resource = this.javaClass.getClassLoader().getResource("hash_code_test_file.txt")

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("CRC-32 알고리즘으로 해싱")
    fun test_crc32() {
        hashTest(CRC32)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD2 알고리즘으로 해싱")
    fun test_md2() {
        hashTest(MD2)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD5 알고리즘으로 해싱")
    fun test_md5() {
        hashTest(MD5)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-1 알고리즘으로 해싱")
    fun test_sha1() {
        hashTest(SHA1)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-224 알고리즘으로 해싱")
    fun test_sha224() {
        hashTest(SHA224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-256 알고리즘으로 해싱")
    fun test_sha256() {
        hashTest(SHA256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-384 알고리즘으로 해싱")
    fun test_sha384() {
        hashTest(SHA384)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512 알고리즘으로 해싱")
    fun test_sha512() {
        hashTest(SHA512)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/224 알고리즘으로 해싱")
    fun test_sha512224() {
        hashTest(SHA512224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/256 알고리즘으로 해싱")
    fun test_sha512256() {
        hashTest(SHA512256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-224 알고리즘으로 해싱")
    fun test_sha3224() {
        hashTest(SHA3224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-256 알고리즘으로 해싱")
    fun test_sha3256() {
        hashTest(SHA3256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-384 알고리즘으로 해싱")
    fun test_sha3384() {
        hashTest(SHA3384)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-512 알고리즘으로 해싱")
    fun test_sha3512() {
        hashTest(SHA3512)
    }

    private fun hashTest(algorithm: EHash) {
        passwordHashTest(algorithm)
        fileHashTest(algorithm)
    }

    private fun passwordHashTest(algorithm: EHash) {
        val h = Hash.getInstance(algorithm)
        assertTrue(h.matches(password.toByteArray(), getHash(algorithm)))
        assertEquals(CodecUtils.encode(h.hash(password), EncodeFormat.HEX), getHash(algorithm))
        assertEquals(CodecUtils.encode(h.hash(password, Charsets.UTF_8), EncodeFormat.HEX), getHash(algorithm))
    }

    private fun fileHashTest(algorithm: EHash) {
        val h = Hash.getInstance(algorithm)
        // assertTrue(h.matches(File(resource?.file ?: ""), h.hash(File(resource?.file ?: ""))))
        // assertFalse(h.matches(File(resource?.file ?: ""), null))
    }

    @Throws(IOException::class)
    private fun getHash(algorithm: EHash): String? {
        val jsonObject = JSONObject(readJson())
        val file = jsonObject.getJSONObject("hash_code_test_file")
        return when (algorithm) {
            CRC32 -> file.getString(CRC32.label())
            MD2 -> file.getString(MD2.label())
            MD5 -> file.getString(MD5.label())
            SHA1 -> file.getString(SHA1.label())
            SHA224 -> file.getString(SHA224.label())
            SHA256 -> file.getString(SHA256.label())
            SHA384 -> file.getString(SHA384.label())
            SHA512 -> file.getString(SHA512.label())
            SHA512224 -> file.getString(SHA512224.label())
            SHA512256 -> file.getString(SHA512256.label())
            SHA3224 -> file.getString(SHA3224.label())
            SHA3256 -> file.getString(SHA3256.label())
            SHA3384 -> file.getString(SHA3384.label())
            SHA3512 -> file.getString(SHA3512.label())
        }
    }

    @Throws(IOException::class)
    private fun readJson(): String {
        if (checksum == null) {
            throw IOException()
        }

        var json: String
        BufferedReader(FileReader(checksum.file)).use { reader ->
            val sb = StringBuilder()
            var line = reader.readLine()
            while (line != null) {
                sb.append(line)
                sb.append("\n")
                line = reader.readLine()
            }
            json = sb.toString()
        }

        return json
    }
}