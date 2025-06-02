package dev.retrotv.crypto.cipher.block.vector

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.algorithm.LEA
import dev.retrotv.crypto.cipher.block.mode.CBC
import dev.retrotv.crypto.cipher.block.mode.ECB
import dev.retrotv.crypto.cipher.param.Param
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.util.stream.Stream

class ECBTest {
    private fun hexToBytes(hex: String): ByteArray = StringUtils.hexStringToByteArray(hex)
    private fun bytesToHex(bytes: ByteArray): String = ByteUtils.toHexString(bytes).uppercase()

    companion object {
        val ALGORITHM = mutableListOf("ARIA", "LEA")
        val KEY_LENGTH = mutableListOf(128, 192, 256)
    }

    @TestFactory
    fun test_ecbKat(): Stream<DynamicTest> {
        val tests = mutableListOf<DynamicTest>()

        CBCTest.Companion.ALGORITHM.forEach { algorithm ->
            val blockCipher = if (algorithm.contentEquals("ARIA")) {
                ARIA()
            } else if (algorithm.contentEquals("LEA")) {
                LEA()
            } else {
                throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }

            CBCTest.Companion.KEY_LENGTH.forEach { keyLength ->
                val file = File("src/vector/$algorithm/${algorithm}-${keyLength}_(ECB)_KAT.txt")
                val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

                var key = ""
                var pt = ""
                var ct: String

                var caseNum = 1
                for (line in lines) {
                    when {
                        line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("CT =") -> {
                            ct = line.substringAfter("=").trim()
                            val testName = "$algorithm-${keyLength}-ECB KAT #$caseNum"
                            val testFn = {
                                val ecb = ECB(blockCipher)
                                val params = Param(hexToBytes(key))
                                val result = ecb.encrypt(hexToBytes(pt), params).data
                                val resultHex = bytesToHex(result)
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
    fun test_ecbMmt(): Stream<DynamicTest> {
        val tests = mutableListOf<DynamicTest>()

        CBCTest.Companion.ALGORITHM.forEach { algorithm ->
            val blockCipher = if (algorithm.contentEquals("ARIA")) {
                ARIA()
            } else if (algorithm.contentEquals("LEA")) {
                LEA()
            } else {
                throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }

            CBCTest.Companion.KEY_LENGTH.forEach { keyLength ->
                val file = File("src/vector/$algorithm/${algorithm}-${keyLength}_(ECB)_MMT.txt")
                val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

                var key = ""
                var pt = ""
                var ct: String

                var caseNum = 1
                for (line in lines) {
                    when {
                        line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("CT =") -> {
                            ct = line.substringAfter("=").trim()
                            val testName = "$algorithm-${keyLength}-ECB MMT #$caseNum"
                            val testFn = {
                                val ecb = ECB(blockCipher)
                                val params = Param(hexToBytes(key))
                                val result = ecb.encrypt(hexToBytes(pt), params).data
                                val resultHex = bytesToHex(result)
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
    fun test_ecbMct(): Stream<DynamicTest> {
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
                val file = File("src/vector/$algorithm/${algorithm}-${keyLength}_(ECB)_MCT.txt")
                val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

                data class MctCase(val count: Int, val key: String, val pt: String, val ct: String)
                val cases = mutableListOf<MctCase>()

                var count = -1
                var key = ""
                var pt = ""
                var ct = ""

                for (line in lines) {
                    when {
                        line.startsWith("COUNT =") -> {
                            if (count != -1) {
                                cases.add(MctCase(count, key, pt, ct))
                            }
                            count = line.substringAfter("=").trim().toInt()
                        }
                        line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("CT =") -> ct = line.substringAfter("=").trim()
                    }
                }

                // 마지막 케이스 추가
                if (count != -1) {
                    cases.add(MctCase(count, key, pt, ct))
                }

                fun hexToBytes(hex: String): ByteArray =
                    hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

                val testCases = cases.map { mctCase ->
                    DynamicTest.dynamicTest("${algorithm}-${keyLength}-ECB MCT COUNT=${mctCase.count}") {
                        val key = hexToBytes(mctCase.key)
                        val pts = Array(1000) { ByteArray(16) }
                        val cts = Array(1000) { ByteArray(16) }
                        pts[0] = hexToBytes(mctCase.pt)

                        val ecb = ECB(blockCipher)
                        for (j in 0 until 1000) {
                            if (j == 0) {
                                cts[0] = ecb.encrypt(pts[0], Param(key)).data.copyOf(16)
                                pts[1] = cts[0]
                            } else {
                                cts[j] = ecb.encrypt(pts[j], Param(key)).data.copyOf(16)
                                if (j != 999) {
                                    pts[j + 1] = cts[j].copyOf()
                                }
                            }
                        }
                        val resultHex = bytesToHex(cts.last())
                        Assertions.assertEquals(mctCase.ct.uppercase(), resultHex, "Failed at COUNT=${mctCase.count} MCT")
                    }
                }.stream()

                testCases.forEach { case -> tests.add(case) }
            }
        }

        return tests.stream()
    }
}