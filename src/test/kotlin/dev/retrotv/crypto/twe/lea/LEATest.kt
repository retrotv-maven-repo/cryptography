package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.ARIAEngine
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.DisplayName
import kotlin.test.Test

class LEATest {

    @Test
    fun test() {
        val cipher2 = LEACBC(128)
        val key = cipher2.generateKey()
        val iv = cipher2.generateSpec()
        val extendedKey = ExtendedSecretKeySpec.toExtendedSecretKeySpec(key)

        val keyBytes = extendedKey.encoded // generate(128 / 8)
        val targetData = "datadatadatadata".toByteArray()

        val cipher1 = CBCBlockCipher.newInstance(LEAEngine())
        cipher1.init(true, ParametersWithIV(KeyParameter(keyBytes), iv.iv))

        val outputData = ByteArray(16)

        println(targetData.size)

        val tam = cipher1.processBlock(targetData, 0, outputData, 0) //.processBlock(targetData, 0, outputData, 0)

        println(toHexString(outputData))
        println(toHexString(cipher2.encrypt(targetData, key, iv)))
    }

    @org.junit.jupiter.api.Test
    @DisplayName("Bouncy Castle 라이브러리와 KISA 라이브러리 암호화 값이 같은지 테스트")
    fun leacbc_is_equal_test() {
        val bouncyCastleCipher = CBCBlockCipher.newInstance(LEAEngine())
        var kisaCipher = LEACBC(128)

        var data = "datadatadatadata".toByteArray()
        var key = kisaCipher.generateKey()
        val iv = kisaCipher.generateSpec()

        var encryptedData1 = kisaCipher.encrypt(data, key, iv)
        var encryptedData2 = ByteArray(16)
        bouncyCastleCipher.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
        bouncyCastleCipher.processBlock(data, 0, encryptedData2, 0)

        println(toHexString(encryptedData1))
        println(toHexString(encryptedData2))

        data = "datadatadatadatadatadatadatadata".toByteArray()
        kisaCipher = LEACBC(256)
        key = kisaCipher.generateKey()
        encryptedData1 = kisaCipher.encrypt(data, key, iv)
        encryptedData2 = ByteArray(32)
        bouncyCastleCipher.init(true, ParametersWithIV(KeyParameter(key.encoded), iv.iv))
        val n = bouncyCastleCipher.processBlocks(data, 0, 0, encryptedData2, 0)
        bouncyCastleCipher.processBlocks(data, 16, n, encryptedData2, 16)

        println(toHexString(encryptedData1))
        println(toHexString(encryptedData2))
    }
}