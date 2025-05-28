package dev.retrotv.crypto.cipher.block.vector

import dev.retrotv.crypto.cipher.block.algorithm.ARIA
import dev.retrotv.crypto.cipher.block.mode.CBC
import dev.retrotv.crypto.cipher.param.ParamWithIV
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
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
                        assertEquals(ct.uppercase(), resultHex.substring(0, halfLength), "Failed at $testName")
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
                        assertEquals(ct.uppercase(), resultHex.substring(0, ctLength), "Failed at $testName")
                    }
                    tests.add(DynamicTest.dynamicTest(testName, testFn))
                    caseNum++
                }
            }
        }
        return tests.stream()
    }

    @Test
    fun test_ariaCbcMct_count0() {
        val file = File("src/vector/ARIA/ARIA-128_(CBC)_MCT.txt")
        val lines = file.readLines().map { it.trim() }.filter { it.isNotEmpty() }

        var keyHex = ""
        var ivHex = ""
        var ptHex = ""
        var ctHex = ""
        var inCount0 = false
        for (line in lines) {
            when {
                line.startsWith("COUNT = 0") -> inCount0 = true
                line.startsWith("COUNT =") && !line.startsWith("COUNT = 0") -> inCount0 = false
                inCount0 && line.startsWith("KEY =") -> keyHex = line.substringAfter("=").trim()
                inCount0 && line.startsWith("IV =") -> ivHex = line.substringAfter("=").trim()
                inCount0 && line.startsWith("PT =") -> ptHex = line.substringAfter("=").trim()
                inCount0 && line.startsWith("CT =") -> ctHex = line.substringAfter("=").trim()
            }
        }

        val key = hexToBytes(keyHex)
        val iv = hexToBytes(ivHex)
        val pts = Array(1000) { ByteArray(16) }
        val cts = Array(1000) { ByteArray(16) }

        pts[0] = hexToBytes(ptHex)

        val aria = ARIA()
        val cbc = CBC(aria)
        for (i in 0 until 1000) {
            if (i == 0) {
                cts[0] = cbc.encrypt(pts[0], ParamWithIV(key, iv)).data.copyOf(16)
                pts[1] = iv
            } else {
                cts[i] = cbc.encrypt(pts[i], ParamWithIV(key, cts[i - 1])).data.copyOf(16)
                if (i != 999) {
                    pts[i + 1] = cts[i - 1].copyOf()
                }
            }
        }

        val resultHex = cts.last().joinToString("") { "%02X".format(it) }
        assertEquals(ctHex.uppercase(), resultHex, "Failed at COUNT=0 MCT")
    }
}
