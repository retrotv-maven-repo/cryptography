package dev.retrotv.crypto.cipher.block.vector

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.algorithm.LEA
import dev.retrotv.crypto.cipher.block.mode.CBC
import dev.retrotv.crypto.cipher.param.ParamWithIV
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.util.stream.Stream

class CBC128Test {
    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        val ALGORITHM = mutableListOf("ARIA", "LEA")
        val KEY_LENGTH = mutableListOf(128, 192, 256)
    }

    @TestFactory
    fun test_cbcKat(): Stream<DynamicTest> {
        val tests = mutableListOf<DynamicTest>()

        ALGORITHM.forEach { algorithm ->
            val blockCipher = if (algorithm.contentEquals("ARIA")) {
                ARIA()
            } else if (algorithm.contentEquals("LEA")) {
                LEA()
            } else {
                throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }

            KEY_LENGTH.forEach { keyLength ->
                val file = File("src/vector/$algorithm/${algorithm}-${keyLength}_(CBC)_KAT.txt")
                val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

                // txt 파일의 KEY, IV, PT, CT 값을 저장할 변수
                var key = ""
                var iv = ""
                var pt = ""
                var ct: String

                var caseNum = 1
                for (line in lines) {
                    when {
                        line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                        line.startsWith("IV =") -> iv = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("CT =") -> {
                            ct = line.substringAfter("=").trim()
                            val testName = "$algorithm-${keyLength}-CBC KAT #$caseNum"
                            val testFn = {
                                val cbc = CBC(blockCipher)
                                val params = ParamWithIV(hexToBytes(key), hexToBytes(iv))
                                val result = cbc.encrypt(hexToBytes(pt), params).data
                                val resultHex = result.joinToString("") { "%02X".format(it) }
                                val ctLength = ct.length
                                Assertions.assertEquals(ct.uppercase(), resultHex.substring(0, ctLength), "Failed at $testName")
                            }
                            tests.add(DynamicTest.dynamicTest(testName, testFn))
                            caseNum++
                        }
                    }
                }
            }
        }

        return tests.stream()
    }

    @TestFactory
    fun test_cbcMmt(): Stream<DynamicTest> {
        val tests = mutableListOf<DynamicTest>()

        ALGORITHM.forEach { algorithm ->
            val blockCipher = if (algorithm.contentEquals("ARIA")) {
                ARIA()
            } else if (algorithm.contentEquals("LEA")) {
                LEA()
            } else {
                throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }

            KEY_LENGTH.forEach { keyLength ->
                val file = File("src/vector/$algorithm/${algorithm}-${keyLength}_(CBC)_MMT.txt")
                val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

                // txt 파일의 KEY, IV, PT, CT 값을 저장할 변수
                var key = ""
                var iv = ""
                var pt = ""
                var ct: String

                var caseNum = 1
                for (line in lines) {
                    when {
                        line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                        line.startsWith("IV =") -> iv = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("CT =") -> {
                            ct = line.substringAfter("=").trim()
                            val testName = "$algorithm-${keyLength}-CBC MMT #$caseNum"
                            val testFn = {
                                val cbc = CBC(blockCipher)
                                val params = ParamWithIV(hexToBytes(key), hexToBytes(iv))
                                val result = cbc.encrypt(hexToBytes(pt), params).data
                                val resultHex = result.joinToString("") { "%02X".format(it) }
                                val ctLength = ct.length
                                Assertions.assertEquals(ct.uppercase(), resultHex.substring(0, ctLength), "Failed at $testName")
                            }
                            tests.add(DynamicTest.dynamicTest(testName, testFn))
                            caseNum++
                        }
                    }
                }
            }
        }

        return tests.stream()
    }
}