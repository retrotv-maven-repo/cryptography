package dev.retrotv.crypto.cipher.block.vector

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.algorithm.LEA
import dev.retrotv.crypto.cipher.block.mode.GCM
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.crypto.cipher.result.AEADResult
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.File
import java.util.stream.Stream

class GCMTest {
    private fun hexToBytes(hex: String): ByteArray = StringUtils.hexStringToByteArray(hex)
    private fun bytesToHex(bytes: ByteArray): String = ByteUtils.toHexString(bytes).uppercase()

    companion object {
        val log: Logger = LoggerFactory.getLogger(GCMTest::class.java)
        val ALGORITHM = mutableListOf("ARIA", "LEA")
        val KEY_LENGTH = mutableListOf(128, 192, 256)
    }

    @TestFactory
    fun test_gcmAd(): Stream<DynamicTest> {
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
                val file = File("src/vector/${algorithm}/GCM_${algorithm}-${keyLength}_AD.txt")
                val lines = file.readLines().map { it.trim() }

                /*
                 * key: 암복호화에 사용되는 비밀 키
                 * iv: 초기화 벡터 (Nonce)
                 * aData: 추가 인증 데이터 (AAD)
                 * c: 암호화된 데이터
                 * t: 인증 태그
                 * pt: 평문 데이터
                 */
                var count = ""
                var key = ""
                var iv = ""
                var aData = ""
                var c = ""
                var t = ""
                var pt = ""

                for (line in lines) {
                    when {
                        line.startsWith("COUNT =") -> count = line.substringAfter("=").trim()
                        line.startsWith("Key =") -> key = line.substringAfter("=").trim()
                        line.startsWith("IV =") -> iv = line.substringAfter("=").trim()
                        line.startsWith("Adata =") -> aData = line.substringAfter("=").trim()
                        line.startsWith("C =") -> c = line.substringAfter("=").trim()
                        line.startsWith("T =") -> t = line.substringAfter("=").trim()
                        line.startsWith("P =") || line.startsWith("Invalid") -> {
                            if (line.startsWith("P =")) {
                                pt = line.substringAfter("=").trim()
                            }
                            if (line.startsWith("P =") || line.startsWith("Invalid")) {
                                val testName = "CCM-${algorithm}-${keyLength}-AD COUNT=$count"

                                log.info("COUNT: $count")
                                log.info("K: $key")
                                log.info("N: $iv")
                                log.info("A: $aData")
                                log.info("C: $c")
                                log.info("Tlen: $t")
                                log.info("P: $pt")
                                log.info("Invalid: ${if (pt.isEmpty()) "true" else "false"}")
                                log.info("테스트 명: $testName")

                                val testFn = {
                                    val gcm = GCM(blockCipher)
                                    gcm.updateAAD(hexToBytes(aData))
                                    val params = ParamWithIV(hexToBytes(key), hexToBytes(iv))
                                    val result = gcm.encrypt(hexToBytes(pt), params).data
                                    val resultHex = bytesToHex(result)

                                    if (pt != "") {
                                        Assertions.assertEquals(c.uppercase(), resultHex, "Failed at $testName")
                                    } else {
                                        Assertions.assertNotEquals(c.uppercase(), resultHex, "Failed at $testName")
                                    }
                                }

                                tests.add(DynamicTest.dynamicTest(testName, testFn))
                                pt = ""
                            }
                        }
                    }
                }
            }
        }

        return tests.stream()
    }

    @TestFactory
    fun test_gcmAe(): Stream<DynamicTest> {
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
                val file = File("src/vector/${algorithm}/GCM_${algorithm}-${keyLength}_AE.txt")
                val lines = file.readLines().map { it.trim() }

                var count = ""
                var key = ""
                var iv = ""
                var pt = ""
                var aData = ""
                var c = ""
                var t: String

                for (line in lines) {
                    when {
                        line.startsWith("COUNT =") -> count = line.substringAfter("=").trim()
                        line.startsWith("Key =") -> key = line.substringAfter("=").trim()
                        line.startsWith("IV =") -> iv = line.substringAfter("=").trim()
                        line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                        line.startsWith("Adata =") -> aData = line.substringAfter("=").trim()
                        line.startsWith("C =") -> c = line.substringAfter("=").trim()
                        line.startsWith("T =") -> {
                            t = line.substringAfter("=").trim()
                            val testName = "CCM-${algorithm}-${keyLength}-AE COUNT=$count"

                            log.info("COUNT: $count")
                            log.info("Key: $key")
                            log.info("IV: $iv")
                            log.info("PT: $pt")
                            log.info("Adata: $aData")
                            log.info("C: $c")
                            log.info("T: $t")
                            log.info("테스트 명: $testName")

                            val testFn = {
                                val gcm = GCM(blockCipher)
                                gcm.updateAAD(hexToBytes(aData))
                                val params = ParamWithIV(hexToBytes(key), hexToBytes(iv))
                                val result = gcm.encrypt(hexToBytes(pt), params)
                                val resultHex = bytesToHex(result.data)
                                val resultTag = bytesToHex((result as AEADResult).tag)

                                Assertions.assertEquals(c.uppercase(), resultHex.replace(resultTag, ""), "Failed at $testName")
                            }

                            tests.add(DynamicTest.dynamicTest(testName, testFn))
                        }
                    }
                }
            }
        }

        return tests.stream()
    }
}