package dev.retrotv.crypto.twe.data

import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.algorithm.AES
import dev.retrotv.crypto.twe.mode.ECB
import io.github.serpro69.kfaker.Faker
import io.github.serpro69.kfaker.fakerConfig
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.RepeatedTest
import kotlin.test.asserter

class PrivacyInformationTest {
    private val config = fakerConfig { locale = "ko-KR" }
    private val faker = Faker(config)

    @DisplayName("이름 AES 암복호화 반복 테스트")
    @RepeatedTest(value = 100, name = "{displayName} : {currentRepetition}/{totalRepetitions}")
    fun test_name() {
        val name = faker.name.name().replace(" ", "")
        println(name)

        val aes128 = AES(128)
        val aes192 = AES(192)
        val aes256 = AES(256)
        val key128 = aes128.generateKey()
        val key192 = aes192.generateKey()
        val key256 = aes256.generateKey()

        val mode = ECB()
        mode.engine = aes128.engine
        var encryptedData = mode.encrypt(name.toByteArray(), Params(key128))
        var originalName = String(mode.decrypt(encryptedData.data, Params(key128)).data)

        asserter.assertEquals("이름이 다릅니다", name, originalName)

        encryptedData = mode.encrypt(name.toByteArray(), Params(key192))
        originalName = String(mode.decrypt(encryptedData.data, Params(key192)).data)

        asserter.assertEquals("이름이 다릅니다", name, originalName)

        encryptedData = mode.encrypt(name.toByteArray(), Params(key256))
        originalName = String(mode.decrypt(encryptedData.data, Params(key256)).data)

        asserter.assertEquals("이름이 다릅니다", name, originalName)
    }
}