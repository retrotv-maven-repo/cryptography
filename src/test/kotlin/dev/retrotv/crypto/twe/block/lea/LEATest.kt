package dev.retrotv.crypto.twe.block.lea

import dev.retrotv.crypto.twe.result.AEADResult
import dev.retrotv.crypto.twe.param.Params
import dev.retrotv.crypto.twe.param.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.algorithm.block.LEA
import dev.retrotv.crypto.twe.mode.*
import dev.retrotv.data.utils.hexStringToByteArray
import dev.retrotv.data.utils.toHexString
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.experimental.xor
import kotlin.test.asserter

class LEATest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private lateinit var lea: BlockCipherAlgorithm

    @DisplayName("ECB 모드 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ecb(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = ECB(this.lea)
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CBC 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cbc(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = CBC(this.lea)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cfb(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = CFB(this.lea)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("OFB 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ofb(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = OFB(this.lea)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTR 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ctr(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = CTR(this.lea)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("CTS 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_cts(keyLen: Int) {

    }

    @DisplayName("CCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_ccm(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = CCM(this.lea)
        val iv = generate(12)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @DisplayName("GCM 모드 암호화 테스트")
    @ValueSource(ints = [128, 192, 256])
    @ParameterizedTest(name = "[{index}] {displayName} - 키 길이: {0}")
    fun test_gcm(keyLen: Int) {
        this.lea = LEA()
        val key = generate(keyLen / 8)
        val mode = GCM(this.lea)
        val iv = generate(12)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv)) as AEADResult
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    fun test() {
        val lea = LEA()
        val key = generate(16)
        val mode = CCM(lea)
        val iv = generate(12)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv)) as AEADResult
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        val mac = CMac(lea.engine)
        mac.init(KeyParameter(key))
        mac.update(message, 0, message.size)
        val macData = ByteArray(mac.macSize)
        mac.doFinal(macData, 0)

        // 517ea1bd615dbeef220a95845b86cbc9
        // 9f615fdfec9954fd9588b1c7c2753cd6
        // fa515800dc26ec1fe956c705b53f40f5

        val result = xorByteArrays(hexStringToByteArray("517ea1bd615dbeef220a95845b86cbc9"), hexStringToByteArray("9f615fdfec9954fd9588b1c7c2753cd6"))

        println(toHexString(result))

        println(toHexString(encryptedData.data))
        println(toHexString(encryptedData.tag))
        println(toHexString(macData))
    }

    private fun xorByteArrays(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "ByteArrays must have the same length" }
        val result = ByteArray(a.size)
        for (i in a.indices) {
            result[i] = (a[i] xor b[i])
        }
        return result
    }
}