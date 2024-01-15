package dev.retrotv.crypto.owe

import dev.retrotv.common.Log
import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.crypto.owe.hash.crc.CRC32
import dev.retrotv.crypto.owe.hash.md.*
import dev.retrotv.crypto.owe.hash.sha.*
import dev.retrotv.enums.Algorithm
import org.json.JSONObject
import org.junit.jupiter.api.Assertions
import org.springframework.security.crypto.password.PasswordEncoder
import java.io.*
import java.net.URISyntaxException
import java.nio.file.Files
import java.util.*

open class OWETest : Log() {
    private val PASSWORD = "The quick brown fox jumps over the lazy dog"
    private val CHECKSUM = this.javaClass.getClassLoader().getResource("hash_code")
    private val RESOURCE = this.javaClass.getClassLoader().getResource("hash_code_test_file.txt")

    @Throws(IOException::class)
    protected fun fileHashTest(algorithm: Algorithm.Hash) {
        var fileData: ByteArray
        val file = try {
            File(Objects.requireNonNull(RESOURCE).toURI())
        } catch (e: URISyntaxException) {
            throw RuntimeException(e)
        }

        try {
            DataInputStream(Files.newInputStream(file.toPath())).use { dis ->
                fileData = ByteArray(file.length().toInt())
                dis.readFully(fileData)
            }
        } catch (e: IOException) {
            throw IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.")
        }

        println(getHash(algorithm))
        println(hash(algorithm, fileData))

        Assertions.assertEquals(getHash(algorithm), hash(algorithm, fileData))
    }

    @Throws(IOException::class)
    protected fun fileHashMatchesTest(fileHash: Hash, algorithm: Algorithm.Hash) {
        var fileData: ByteArray
        val file = try {
            File(Objects.requireNonNull(RESOURCE).toURI())
        } catch (e: URISyntaxException) {
            throw RuntimeException(e)
        }

        try {
            DataInputStream(Files.newInputStream(file.toPath())).use { dis ->
                fileData = ByteArray(file.length().toInt())
                dis.readFully(fileData)
            }
        } catch (e: IOException) {
            throw IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.")
        }

        Assertions.assertTrue(fileHash.matches(fileData, getHash(algorithm)))
    }

    protected fun passwordEncryptAndMatchesTest(password: PasswordEncoder) {
        val encryptedPassword = password.encode(PASSWORD)
        log.info(encryptedPassword)

        Assertions.assertNotEquals(PASSWORD, encryptedPassword)
        Assertions.assertTrue(password.matches(PASSWORD, encryptedPassword))
    }

    private fun hash(algorithm: Algorithm.Hash, fileData: ByteArray): String? {
        return when (algorithm) {
            Algorithm.Hash.CRC32 -> {
                val hash: Hash = CRC32()
                hash.hash(fileData)
            }

            Algorithm.Hash.MD2 -> {
                val hash: Hash = MD2()
                hash.hash(fileData)
            }

            Algorithm.Hash.MD5 -> {
                val hash: Hash = MD5()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA1 -> {
                val hash: Hash = SHA1()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA224 -> {
                val hash: Hash = SHA224()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA256 -> {
                val hash: Hash = SHA256()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA384 -> {
                val hash: Hash = SHA384()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA512 -> {
                val hash: Hash = SHA512()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA512224 -> {
                val hash: Hash = SHA512224()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA512256 -> {
                val hash: Hash = SHA512256()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA3224 -> {
                val hash: Hash = SHA3224()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA3256 -> {
                val hash: Hash = SHA3256()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA3384 -> {
                val hash: Hash = SHA3384()
                hash.hash(fileData)
            }

            Algorithm.Hash.SHA3512 -> {
                val hash: Hash = SHA3512()
                hash.hash(fileData)
            }

            else -> null
        }
    }

    @Throws(IOException::class)
    private fun getHash(algorithm: Algorithm.Hash): String? {
        val jsonObject = JSONObject(readJson())
        val file1 = jsonObject.getJSONObject("hash_code_test_file")
        return when (algorithm) {
            Algorithm.Hash.CRC32 -> file1.getString(Algorithm.Hash.CRC32.label())
            Algorithm.Hash.MD2 -> file1.getString(Algorithm.Hash.MD2.label())
            Algorithm.Hash.MD5 -> file1.getString(Algorithm.Hash.MD5.label())
            Algorithm.Hash.SHA1 -> file1.getString(Algorithm.Hash.SHA1.label())
            Algorithm.Hash.SHA224 -> file1.getString(Algorithm.Hash.SHA224.label())
            Algorithm.Hash.SHA256 -> file1.getString(Algorithm.Hash.SHA256.label())
            Algorithm.Hash.SHA384 -> file1.getString(Algorithm.Hash.SHA384.label())
            Algorithm.Hash.SHA512 -> file1.getString(Algorithm.Hash.SHA512.label())
            Algorithm.Hash.SHA512224 -> file1.getString(Algorithm.Hash.SHA512224.label())
            Algorithm.Hash.SHA512256 -> file1.getString(Algorithm.Hash.SHA512256.label())
            Algorithm.Hash.SHA3224 -> file1.getString(Algorithm.Hash.SHA3224.label())
            Algorithm.Hash.SHA3256 -> file1.getString(Algorithm.Hash.SHA3256.label())
            Algorithm.Hash.SHA3384 -> file1.getString(Algorithm.Hash.SHA3384.label())
            Algorithm.Hash.SHA3512 -> file1.getString(Algorithm.Hash.SHA3512.label())
            else -> null
        }
    }

    @Throws(IOException::class)
    private fun readJson(): String {
        if (CHECKSUM == null) {
            throw IOException()
        }

        var json: String
        BufferedReader(FileReader(CHECKSUM.file)).use { reader ->
            val sb = StringBuilder()
            var line = reader.readLine()
            while (line != null) {
                sb.append(line)
                sb.append("\n")
                line = reader.readLine()
            }
            json = sb.toString()
        }

        log.info(json)
        return json
    }
}
