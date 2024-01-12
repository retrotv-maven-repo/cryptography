package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.ARIAEngine
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
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
}