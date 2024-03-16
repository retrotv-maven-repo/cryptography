package dev.retrotv.crypto.twe.block.seed

import dev.retrotv.crypto.twe.AEADResult
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.algorithm.BlockCipherAlgorithm
import dev.retrotv.crypto.twe.algorithm.block.SEED
import dev.retrotv.crypto.twe.generator.generateIV
import dev.retrotv.crypto.twe.generator.generateKey
import dev.retrotv.crypto.twe.mode.*
import dev.retrotv.utils.generate
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test
import kotlin.test.asserter

class SEEDTest {
    private val message = "The lazy dog jumps over the brown fox!".toByteArray()
    private lateinit var seed: BlockCipherAlgorithm

    @Test
    @DisplayName("ECB 모드 테스트")
    fun test_ecb() {
        this.seed = SEED()
        val key = generate(16)
        val mode = ECB(this.seed)
        val encryptedData = mode.encrypt(message, Params(key))
        val originalData = mode.decrypt(encryptedData.data, Params(key))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CBC 모드 암호화 테스트")
    fun test_cbc() {
        this.seed = SEED()
        val key = generate(16)
        val mode = CBC(this.seed)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CFB 모드 암호화 테스트")
    fun test_cfb() {
        this.seed = SEED()
        val key = generate(16)
        val mode = CFB(this.seed)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("OFB 모드 암호화 테스트")
    fun test_ofb() {
        this.seed = SEED()
        val key = generate(16)
        val mode = OFB(this.seed)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTR 모드 암호화 테스트")
    fun test_ctr() {
        this.seed = SEED()
        val key = generate(16)
        val mode = CTR(this.seed)
        val iv = generate(16)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CTS 모드 암호화 테스트")
    fun test_cts() {

        /*
         * CTS 모드는 엔진을 CBCBlockCipher.newInstance()로 감싸서 사용할 수 있다.
         * 이 때, CBC 모드로 패딩한다면 key + iv 값이 필요하며, EBS 모드만 사용하면 key 값만 있으면 된다.
         * 또한, 블록 사이즈 보다 데이터 크기가 작으면 사용할 수 없다. 이 경우에는 iv 값을 데이터 끝에 패딩하는 식으로 사용해야 한다.
         */

        this.seed = SEED()
        val key = generate(16)
        val mode = CTS(this.seed)
        val iv = generate(16)
        mode.useCBCMode()
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("CCM 모드 암호화 테스트")
    fun test_ccm() {
        this.seed = SEED()
        val key = generateKey(seed.algorithm, 16)
        val mode = CCM(this.seed)
        val iv = generateIV(seed.algorithm, mode.mode)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv))
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }

    @Test
    @DisplayName("GCM 모드 암호화 테스트")
    fun test_gcm() {
        this.seed = SEED()
        val key = generate(16)
        val mode = GCM(this.seed)
        val iv = generate(12)
        val encryptedData = mode.encrypt(message, ParamsWithIV(key, iv)) as AEADResult
        val originalData = mode.decrypt(encryptedData.data, ParamsWithIV(key, iv))

        asserter.assertEquals("동일한 메시지가 아닙니다.", String(message), String(originalData.data))
    }
}