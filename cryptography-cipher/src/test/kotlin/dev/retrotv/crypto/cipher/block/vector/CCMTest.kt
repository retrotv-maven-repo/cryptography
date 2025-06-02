package dev.retrotv.crypto.cipher.block.vector

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.mode.CCM
import dev.retrotv.crypto.cipher.param.ParamWithIV
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.util.stream.Stream
import kotlin.collections.get
import kotlin.test.assertEquals

class CCMTest {
    private fun hexToBytes(hex: String): ByteArray = StringUtils.hexStringToByteArray(hex)
    private fun bytesToHex(bytes: ByteArray): String = ByteUtils.toHexString(bytes).uppercase()

    data class CcmVector(
        val count: String,
        val k: String,
        val n: String,
        val a: String,
        val c: String,
        val tlen: String,
        val p: String?,         // P가 없을 수도 있으므로 nullable
        val invalid: Boolean    // INVALID 여부
    )

    @TestFactory
    fun test_ccmVectors(): Stream<DynamicTest> {
        val tests = mutableListOf<DynamicTest>()
        val file = File("src/vector/ARIA/CCM_ARIA-128_DV.txt")
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
                        val testName = "CCM-ARIA-128 COUNT=$count"
                        val testFn = {
                            val ccm = CCM(ARIA())
                            ccm.updateAAD(hexToBytes(a))
                            ccm.updateTagLength(tLen)
                            val params = ParamWithIV(hexToBytes(k), hexToBytes(n))
                            val result = ccm.encrypt(hexToBytes(p), params).data
                            val resultHex = bytesToHex(result)

                            if (p != "") {
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

        return tests.stream()
    }
}