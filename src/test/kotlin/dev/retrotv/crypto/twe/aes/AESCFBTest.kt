package dev.retrotv.crypto.twe.aes

import dev.retrotv.common.Log
import org.junit.jupiter.api.*
import java.security.spec.AlgorithmParameterSpec

@TestInstance(value = TestInstance.Lifecycle.PER_CLASS)
internal class AESCFBTest : Log() {
    private val encryptedAllData128: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData192: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData256: MutableSet<ByteArray> = HashSet()

    @DisplayName("AES/CFB-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aescfb128_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESCFB(128)
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

    @DisplayName("AES/CFB-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aescfb192_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESCFB(192)
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

    @DisplayName("AES/CFB-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aescfb256_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESCFB(256)
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
}
