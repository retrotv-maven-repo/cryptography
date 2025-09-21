import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.algorithm.LEA
import dev.retrotv.crypto.cipher.block.mode.CCM
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.File
import java.util.*
import java.util.stream.Stream

class CCMTest {
    private fun hexToBytes(hex: String): ByteArray = StringUtils.hexToByteArray(hex)
    private fun bytesToHex(bytes: ByteArray): String = ByteUtils.toHexString(bytes).uppercase()

    companion object {
        val log: Logger = LoggerFactory.getLogger(CCMTest::class.java)
        val ALGORITHM = mutableListOf("ARIA", "LEA")
        val KEY_LENGTH = mutableListOf(128, 192, 256)
    }

    @TestFactory
    fun test_ccmDv(): Stream<DynamicTest> {
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
                val file = File("src/vector/${algorithm}/CCM_${algorithm}-${keyLength}_DV.txt")
                val lines = file.readLines().map { it.trim() }

                var count = ""
                var k = ""
                var n = ""
                var a = ""
                var c = ""
                var tLen = 0
                var p = ""

                for (line in lines) {
                    when {
                        line.startsWith("COUNT =") -> count = line.substringAfter("=").trim()
                        line.startsWith("K =") -> k = line.substringAfter("=").trim()
                        line.startsWith("N =") -> n = line.substringAfter("=").trim()
                        line.startsWith("A =") -> a = line.substringAfter("=").trim()
                        line.startsWith("C =") -> c = line.substringAfter("=").trim()
                        line.startsWith("Tlen =") -> tLen = line.substringAfter("=").trim().toInt() / 8
                        line.startsWith("P =") || line.startsWith("INVALID") -> {
                            if (line.startsWith("P =")) {
                                p = line.substringAfter("=").trim()
                            }
                            if (line.startsWith("P =") || line.startsWith("INVALID")) {
                                val testName = "CCM-${algorithm}-${keyLength}-DV COUNT=$count"

                                log.info("COUNT: $count")
                                if (count == "3") {
                                    log.info("K: $k")
                                    log.info("N: $n")
                                    log.info("A: $a")
                                    log.info("C: $c")
                                    log.info("Tlen: $tLen")
                                    log.info("P: $p")
                                    log.info("INVALID: ${if (p.isEmpty()) "true" else "false"}")
                                    log.info("테스트 명: $testName")
                                    log.info("{}", p == "");
                                    log.info("{}", p == null);
                                    log.info("{}", c);

                                }

                                val testFn = {
                                    val ccm = CCM(blockCipher)
                                    ccm.updateAAD(hexToBytes(a))
                                    ccm.updateTagLength(tLen)
                                    val params = ParamWithIV(hexToBytes(k), hexToBytes(n))
                                    val result = ccm.encrypt(hexToBytes(p), params).data
                                    val resultHex = bytesToHex(result)

                                    if (p != "") {
                                        log.info("{}", resultHex)
                                        Assertions.assertEquals(c.uppercase(), resultHex, "Failed at $testName")
                                    } else {
                                        Assertions.assertNotEquals(c.uppercase(), resultHex, "Failed at $testName")
                                    }
                                }

                                // 캡처 시점에 p, a, k, n, c, tLen 값을 복사해서 클로저에 전달
                                tests.add(DynamicTest.dynamicTest(testName, testFn))
                                p = ""
                            }
                        }
                    }
                }
            }
        }

        return tests.stream()
    }

    @TestFactory
    fun test_ccmGe(): Stream<DynamicTest> {
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
                val file = File("src/vector/${algorithm}/CCM_${algorithm}-${keyLength}_GE.txt")
                val lines = file.readLines().map { it.trim() }

                var count = ""
                var k = ""
                var n = ""
                var a = ""
                var p = ""
                var tLen = 0
                var c: String

                for (line in lines) {
                    when {
                        line.startsWith("COUNT =") -> count = line.substringAfter("=").trim()
                        line.startsWith("K =") -> k = line.substringAfter("=").trim()
                        line.startsWith("N =") -> n = line.substringAfter("=").trim()
                        line.startsWith("A =") -> a = line.substringAfter("=").trim()
                        line.startsWith("P =") -> p = line.substringAfter("=").trim()
                        line.startsWith("Tlen =") -> tLen = line.substringAfter("=").trim().toInt() / 8
                        line.startsWith("C =") -> {
                            c = line.substringAfter("=").trim()
                            val testName = "CCM-${algorithm}-${keyLength}-GE COUNT=$count"

                            log.info("COUNT: $count")
                            log.info("K: $k")
                            log.info("N: $n")
                            log.info("A: $a")
                            log.info("P: $p")
                            log.info("Tlen: $tLen")
                            log.info("C: $c")
                            log.info("테스트 명: $testName")

                            val testFn = {
                                val ccm = CCM(blockCipher)
                                ccm.updateAAD(hexToBytes(a))
                                ccm.updateTagLength(tLen)
                                val params = ParamWithIV(hexToBytes(k), hexToBytes(n))
                                val result = ccm.encrypt(hexToBytes(p), params).data
                                val resultHex = bytesToHex(result)

                                Assertions.assertEquals(c.uppercase(), resultHex, "Failed at $testName")
                            }

                            // 캡처 시점에 p, a, k, n, c, tLen 값을 복사해서 클로저에 전달
                            tests.add(DynamicTest.dynamicTest(testName, testFn))
                        }
                    }
                }
            }
        }

        return tests.stream()
    }
}