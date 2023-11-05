package dev.retrotv.crypto.twe.aes

import dev.retrotv.common.Log
import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.enums.EncodeFormat
import org.junit.jupiter.api.*

@TestInstance(value = TestInstance.Lifecycle.PER_CLASS)
internal class AESECBTest : Log() {
    private val encryptedAllData128: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData192: MutableSet<ByteArray> = HashSet()
    private val encryptedAllData256: MutableSet<ByteArray> = HashSet()

    @DisplayName("AES/ECB-128 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesecb128_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESECB(128)
        val key = aes.generateKey()
        aes.dataPadding()
        val encryptedData = aes.encrypt(message.toByteArray(), key, null)
        val originalMessage = String(aes.decrypt(encryptedData, key, null))
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

    @DisplayName("AES/ECB-192 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesecb192_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESECB(192)
        val key = aes.generateKey()
        aes.dataPadding()
        val encryptedData = aes.encrypt(message.toByteArray(), key, null)
        val originalMessage = String(aes.decrypt(encryptedData, key, null))
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

    @DisplayName("AES/ECB-256 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun aesecb256_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESECB(256)
        val key = aes.generateKey()
        aes.dataPadding()
        val encryptedData = aes.encrypt(message.toByteArray(), key, null)
        val originalMessage = String(aes.decrypt(encryptedData, key, null))
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
    @DisplayName("EncodeFormat 지정 테스트")
    @Throws(
        CryptoFailException::class
    )
    fun encode_format_test() {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AESECB(128)
        val key = aes.generateKey()
        aes.dataPadding()
        val encryptedData = aes.encrypt(message.toByteArray(), key, null, EncodeFormat.BASE64)
        val originalMessage = String(aes.decrypt(encryptedData, key, null, EncodeFormat.BASE64))
        Assertions.assertEquals(message, originalMessage)
    }
}
