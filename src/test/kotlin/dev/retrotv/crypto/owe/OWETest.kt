package dev.retrotv.crypto.owe

import dev.retrotv.common.Log
import dev.retrotv.crypto.owe.hash.Checksum
import dev.retrotv.crypto.owe.hash.FileChecksum
import dev.retrotv.crypto.owe.hash.crc.CRC32
import dev.retrotv.crypto.owe.hash.md.MD2
import dev.retrotv.crypto.owe.hash.md.MD5
import dev.retrotv.crypto.owe.hash.sha.*
import dev.retrotv.enums.HashAlgorithm
import org.json.JSONObject
import org.junit.jupiter.api.Assertions
import org.springframework.security.crypto.password.PasswordEncoder
import java.io.*
import java.net.URISyntaxException
import java.nio.file.Files
import java.util.*

open class OWETest : Log() {
    protected val PASSWORD = "The quick brown fox jumps over the lazy dog"
    protected val CHECKSUM = this.javaClass.getClassLoader().getResource("checksum")
    protected val RESOURCE = this.javaClass.getClassLoader().getResource("checksum_test_file.txt")
    protected val RESOURCE2 = this.javaClass.getClassLoader().getResource("checksum_test_file2.txt")
    @Throws(IOException::class)
    protected fun fileHashTest(algorithm: HashAlgorithm) {
        val file: File
        var fileData: ByteArray
        file = try {
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
        Assertions.assertEquals(getHash(algorithm), hash(algorithm, fileData))
    }

    @Throws(IOException::class)
    protected fun fileHashMatchesTest(checksum: Checksum, algorithm: HashAlgorithm) {
        val file: File
        var fileData: ByteArray
        file = try {
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
        Assertions.assertTrue(checksum.matches(fileData, getHash(algorithm)))
    }

    @Throws(IOException::class)
    protected fun fileMatchesTest(checksum: FileChecksum) {
        if (RESOURCE != null && RESOURCE2 != null) {
            Assertions.assertTrue(checksum.matches(File(RESOURCE.file), File(RESOURCE2.file)))
        } else {
            Assertions.fail<Any>()
        }
    }

    protected fun passwordEncryptAndMatchesTest(password: PasswordEncoder) {
        val encryptedPassword = password.encode(PASSWORD)
        log.info(encryptedPassword)
        Assertions.assertNotEquals(PASSWORD, encryptedPassword)
        Assertions.assertTrue(password.matches(PASSWORD, encryptedPassword))
    }

    private fun hash(algorithm: HashAlgorithm, fileData: ByteArray): String? {
        return when (algorithm) {
            HashAlgorithm.CRC32 -> {
                val checksum: Checksum = CRC32()
                checksum.hash(fileData)
            }

            HashAlgorithm.MD2 -> {
                val checksum: Checksum = MD2()
                checksum.hash(fileData)
            }

            HashAlgorithm.MD5 -> {
                val checksum: Checksum = MD5()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA1 -> {
                val checksum: Checksum = SHA1()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA224 -> {
                val checksum: Checksum = SHA224()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA256 -> {
                val checksum: Checksum = SHA256()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA384 -> {
                val checksum: Checksum = SHA384()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA512 -> {
                val checksum: Checksum = SHA512()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA512224 -> {
                val checksum: Checksum = SHA512224()
                checksum.hash(fileData)
            }

            HashAlgorithm.SHA512256 -> {
                val checksum: Checksum = SHA512256()
                checksum.hash(fileData)
            }

            else -> null
        }
    }

    @Throws(IOException::class)
    private fun getHash(algorithm: HashAlgorithm): String? {
        val jsonObject = JSONObject(readJson())
        val file1 = jsonObject.getJSONObject("checksum_test_file")
        return when (algorithm) {
            HashAlgorithm.CRC32 -> file1.getString(HashAlgorithm.CRC32.label())
            HashAlgorithm.MD2 -> file1.getString(HashAlgorithm.MD2.label())
            HashAlgorithm.MD5 -> file1.getString(HashAlgorithm.MD5.label())
            HashAlgorithm.SHA1 -> file1.getString(HashAlgorithm.SHA1.label())
            HashAlgorithm.SHA224 -> file1.getString(HashAlgorithm.SHA224.label())
            HashAlgorithm.SHA256 -> file1.getString(HashAlgorithm.SHA256.label())
            HashAlgorithm.SHA384 -> file1.getString(HashAlgorithm.SHA384.label())
            HashAlgorithm.SHA512 -> file1.getString(HashAlgorithm.SHA512.label())
            HashAlgorithm.SHA512224 -> file1.getString(HashAlgorithm.SHA512224.label())
            HashAlgorithm.SHA512256 -> file1.getString(HashAlgorithm.SHA512256.label())
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
