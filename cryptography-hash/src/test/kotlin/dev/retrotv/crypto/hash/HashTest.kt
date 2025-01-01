package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.*
import dev.retrotv.crypto.exception.AlgorithmNotFoundException
import dev.retrotv.crypto.util.CodecUtils
import dev.retrotv.data.enums.EncodeFormat

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import java.io.BufferedReader
import java.io.FileReader
import java.io.IOException

class HashTest {
    private val password = "The quick brown fox jumps over the lazy dog"
    private val checksum = this.javaClass.getClassLoader().getResource("hashing_code")
    private val resource = this.javaClass.getClassLoader().getResource("hashing_code_test_file.txt")

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("CRC-32 알고리즘으로 해싱")
    fun test_crc32() {
        hashingTest(CRC32)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD2 알고리즘으로 해싱")
    fun test_md2() {
        hashingTest(MD2)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("MD5 알고리즘으로 해싱")
    fun test_md5() {
        hashingTest(MD5)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-1 알고리즘으로 해싱")
    fun test_sha1() {
        hashingTest(SHA1)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-224 알고리즘으로 해싱")
    fun test_sha224() {
        hashingTest(SHA224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-256 알고리즘으로 해싱")
    fun test_sha256() {
        hashingTest(SHA256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-384 알고리즘으로 해싱")
    fun test_sha384() {
        hashingTest(SHA384)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512 알고리즘으로 해싱")
    fun test_sha512() {
        hashingTest(SHA512)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/224 알고리즘으로 해싱")
    fun test_sha512224() {
        hashingTest(SHA512224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA-512/256 알고리즘으로 해싱")
    fun test_sha512256() {
        hashingTest(SHA512256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-224 알고리즘으로 해싱")
    fun test_sha3224() {
        hashingTest(SHA3224)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-256 알고리즘으로 해싱")
    fun test_sha3256() {
        hashingTest(SHA3256)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-384 알고리즘으로 해싱")
    fun test_sha3384() {
        hashingTest(SHA3384)
    }

    @RepeatedTest(100, name = "{displayName} {currentRepetition}/{totalRepetitions}")
    @DisplayName("SHA3-512 알고리즘으로 해싱")
    fun test_sha3512() {
        hashingTest(SHA3512)
    }

    @Test
    @DisplayName("getInstance(String) 테스트")
    fun test_getInstance() {
        val h1 = Hash.getInstance("MD5")
        val h2 = Hash.getInstance(MD5)

        assertEquals(CodecUtils.encode(h1.hashing(this.password)), CodecUtils.encode(h2.hashing(this.password)))
    }

    @Test
    @DisplayName("AlgorithmNotFoundException 테스트")
    fun test_algorithmNotFoundException() {
        assertThrows(AlgorithmNotFoundException::class.java) {
            Hash.getInstance("WRONG_ALGORITHM")
        }
    }

    private fun hashingTest(algorithm: EHash) {
        passwordHashTest(algorithm)
        fileHashTest(algorithm)
    }

    private fun passwordHashTest(algorithm: EHash) {
        val h = Hash.getInstance(algorithm)
        assertTrue(h.matches(password.toByteArray(), getHash(algorithm)))
        assertEquals(CodecUtils.encode(h.hashing(password), EncodeFormat.HEX), getHash(algorithm))
        assertEquals(CodecUtils.encode(h.hashing(password, Charsets.UTF_8), EncodeFormat.HEX), getHash(algorithm))
    }

    private fun fileHashTest(algorithm: EHash) {
        val h: BinaryHash = Hash.getInstance(algorithm)
        assertTrue(
            h.matches(
                resource?.file!!.toByteArray(),
                CodecUtils.encode(h.hashing(resource.file!!.toByteArray()))
            )
        )

        assertFalse(h.matches(resource.file!!.toByteArray(), null as ByteArray?))
        assertFalse(h.matches(resource.file!!.toByteArray(), null as String?, EncodeFormat.HEX))
    }

    @Throws(IOException::class)
    private fun getHash(algorithm: EHash): String? {
        val jsonObject = JSONObject(readJson())
        val file = jsonObject.getJSONObject("hashing_code_test_file")
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