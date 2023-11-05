package dev.retrotv.crypto.twe.des

import dev.retrotv.common.Log
import org.junit.jupiter.api.*
import java.security.spec.AlgorithmParameterSpec

@TestInstance(value = TestInstance.Lifecycle.PER_CLASS)
internal class TripleDESCFBTest : Log() {
    private val encryptedAllData: MutableSet<ByteArray> = HashSet()

    @DisplayName("DESede/CFB 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{currentRepetition}/{totalRepetitions}")
    @Throws(
        Exception::class
    )
    fun triple_descfb_100_repeat_test(repetitionInfo: RepetitionInfo) {
        val message = "The lazy dog jumps over the brown fox!"
        val des = TripleDESCFB()
        val key = des.generateKey()
        val spec: AlgorithmParameterSpec = des.generateSpec()
        val encryptedData = des.encrypt(message.toByteArray(), key!!, spec)
        val originalMessage = String(des.decrypt(encryptedData, key, spec))
        Assertions.assertEquals(message, originalMessage)
        encryptedAllData.add(encryptedData)
        if (repetitionInfo.currentRepetition == repetitionInfo.totalRepetitions) {
            log.info("마지막 테스트")
            log.info("총 테스트 횟수: " + repetitionInfo.currentRepetition)
            log.info("암호화 된 데이터 개수 : " + encryptedAllData.size)
            if (repetitionInfo.totalRepetitions != encryptedAllData.size) {
                Assertions.fail<Any>()
            }
            encryptedAllData.clear()
        }
    }
}
