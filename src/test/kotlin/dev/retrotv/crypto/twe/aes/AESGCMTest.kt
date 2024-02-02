package dev.retrotv.crypto.twe.aes

import dev.retrotv.common.Log
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.*
import java.security.spec.AlgorithmParameterSpec

@TestInstance(value = TestInstance.Lifecycle.PER_CLASS)
internal class AESGCMTest : Log() {
    private val encryptedAllData128: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData192: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData256: MutableSet<ByteArray> = HashSet()

    @DisplayName("AES/GCM-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesgcm128_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESGCM(128)
        val key = aes.generateKey()
        val spec: AlgorithmParameterSpec = aes.generateSpec()
        val encryptedData = aes.encrypt(message.toByteArray(), key, spec)
        val originalMessage = String(aes.decrypt(encryptedData, key, spec))
        Assertions.assertEquals(message, originalMessage)
        encryptedAllData128.add(encryptedData)
        if (repetitionInfo.currentRepetition == repetitionInfo.totalRepetitions) {
            log.info("마지막 테스트")
            log.info("총 테스트 횟수: " + repetitionInfo.currentRepetition)
            log.info("암호화 된 데이터 개수 : " + encryptedAllData128.size)
            if (repetitionInfo.totalRepetitions != encryptedAllData128.size) {
                Assertions.fail<Any>()
            }
            encryptedAllData128.clear()
        }
    }

    @DisplayName("AES/GCM-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesgcm192_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESGCM(192)
        val key = aes.generateKey()
        val spec: AlgorithmParameterSpec = aes.generateSpec()
        val encryptedData = aes.encrypt(message.toByteArray(), key, spec)
        val originalMessage = String(aes.decrypt(encryptedData, key, spec))
        Assertions.assertEquals(message, originalMessage)
        encryptedAllData192.add(encryptedData)
        if (repetitionInfo.currentRepetition == repetitionInfo.totalRepetitions) {
            log.info("마지막 테스트")
            log.info("총 테스트 횟수: " + repetitionInfo.currentRepetition)
            log.info("암호화 된 데이터 개수 : " + encryptedAllData192.size)
            if (repetitionInfo.totalRepetitions != encryptedAllData192.size) {
                Assertions.fail<Any>()
            }
            encryptedAllData192.clear()
        }
    }

    @DisplayName("AES/GCM-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesgcm256_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESGCM(256)
        val key = aes.generateKey()
        val spec: AlgorithmParameterSpec = aes.generateSpec()
        val encryptedData = aes.encrypt(message.toByteArray(), key, spec)
        val originalMessage = String(aes.decrypt(encryptedData, key, spec))
        Assertions.assertEquals(message, originalMessage)
        encryptedAllData256.add(encryptedData)
        if (repetitionInfo.currentRepetition == repetitionInfo.totalRepetitions) {
            log.info("마지막 테스트")
            log.info("총 테스트 횟수: " + repetitionInfo.currentRepetition)
            log.info("암호화 된 데이터 개수 : " + encryptedAllData256.size)
            if (repetitionInfo.totalRepetitions != encryptedAllData256.size) {
                Assertions.fail<Any>()
            }
            encryptedAllData256.clear()
        }
    }

    @Test
    fun aesgcm() {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESGCM(256)
        val key = aes.generateKey()
        val spec = aes.generateSpec()
        val aad = "01234567890123456"
            aes.updateAAD(aad)
        val encryptedData = aes.encrypt(message.toByteArray(), key, spec)

        println(toHexString(encryptedData))

        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())

            // aad 값이 존재하면 자동으로 updateAAD가 된다
            cipher.init(true, AEADParameters(KeyParameter(key.encoded), 128, spec.iv, aad.toByteArray()))

        val outputData = ByteArray(cipher.getOutputSize(message.toByteArray().size))
        var tam = cipher.processBytes(message.toByteArray(), 0, message.toByteArray().size, outputData, 0)
            tam += cipher.doFinal(outputData, tam)

        println(toHexString(outputData))
        println(toHexString(cipher.mac))
    }
}
