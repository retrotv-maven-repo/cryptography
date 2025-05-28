package dev.retrotv.crypto.cipher.block.vector.aria

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.mode.CBC
import dev.retrotv.crypto.cipher.param.ParamWithIV
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.util.stream.Stream

class ARIA128CBCTest {
    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @TestFactory
    fun test_ariaCbcKat(): Stream<DynamicTest> {
        val file = File("src/vector/ARIA/ARIA-128_(CBC)_KAT.txt")
        val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }
        val tests = mutableListOf<DynamicTest>()

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
                    val testName = "ARIA-128-CBC KAT #$caseNum"
                    val testFn = {
                        val aria = ARIA()
                        val cbc = CBC(aria)
                        val params = ParamWithIV(hexToBytes(key), hexToBytes(iv))
                        val result = cbc.encrypt(hexToBytes(pt), params).data
                        val resultHex = result.joinToString("") { "%02X".format(it) }
                        val halfLength = resultHex.length / 2
                        Assertions.assertEquals(
                            ct.uppercase(),
                            resultHex.substring(0, halfLength),
                            "Failed at $testName"
                        )
                    }
                    tests.add(DynamicTest.dynamicTest(testName, testFn))
                    caseNum++
                }
            }
        }
        return tests.stream()
    }

    @TestFactory
    fun test_ariaCbcMmt(): Stream<DynamicTest> {
        val file = File("src/vector/ARIA/ARIA-128_(CBC)_MMT.txt")
        val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }
        val tests = mutableListOf<DynamicTest>()

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
                    val testName = "ARIA-128-CBC MMT #$caseNum"
                    val testFn = {
                        val aria = ARIA()
                        val cbc = CBC(aria)
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
        return tests.stream()
    }

    @TestFactory
    fun test_ariaCbcMct_allCounts(): Stream<DynamicTest> {
        val file = File("src/vector/ARIA/ARIA-128_(CBC)_MCT.txt")
        val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

        data class MctCase(val count: Int, val key: String, val iv: String, val pt: String, val ct: String)
        val cases = mutableListOf<MctCase>()

        var count = -1
        var key = ""
        var iv = ""
        var pt = ""
        var ct = ""
        for (line in lines) {
            when {
                line.startsWith("COUNT =") -> {
                    if (count != -1) {
                        cases.add(MctCase(count, key, iv, pt, ct))
                    }
                    count = line.substringAfter("=").trim().toInt()
                }
                line.startsWith("KEY =") -> key = line.substringAfter("=").trim()
                line.startsWith("IV =") -> iv = line.substringAfter("=").trim()
                line.startsWith("PT =") -> pt = line.substringAfter("=").trim()
                line.startsWith("CT =") -> ct = line.substringAfter("=").trim()
            }
        }

        // 마지막 케이스 추가
        if (count != -1) {
            cases.add(MctCase(count, key, iv, pt, ct))
        }

        fun hexToBytes(hex: String): ByteArray =
            hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        return cases.map { mctCase ->
            DynamicTest.dynamicTest("ARIA-128-CBC MCT COUNT=${mctCase.count}") {
                val key = hexToBytes(mctCase.key)
                val iv = hexToBytes(mctCase.iv)
                val pts = Array(1000) { ByteArray(16) }
                val cts = Array(1000) { ByteArray(16) }
                pts[0] = hexToBytes(mctCase.pt)

                val aria = ARIA()
                val cbc = CBC(aria)
                for (j in 0 until 1000) {
                    if (j == 0) {
                        cts[0] = cbc.encrypt(pts[0], ParamWithIV(key, iv)).data.copyOf(16)
                        pts[1] = iv
                    } else {
                        cts[j] = cbc.encrypt(pts[j], ParamWithIV(key, cts[j - 1])).data.copyOf(16)
                        if (j != 999) {
                            pts[j + 1] = cts[j - 1].copyOf()
                        }
                    }
                }
                val resultHex = cts.last().joinToString("") { "%02X".format(it) }
                Assertions.assertEquals(mctCase.ct.uppercase(), resultHex, "Failed at COUNT=${mctCase.count} MCT")
            }
        }.stream()
    }
}