package dev.retrotv.crypto.twe.aria

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.lea.LEA
import dev.retrotv.crypto.twe.mode.CBC
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.ARIAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import kotlin.test.Test

class ARIATest {

    @Test
    fun test() {
        val keyBytes = "keyskeyskeyskeys".toByteArray() // generate(128 / 8)
        val iv = "iviviviviviviviv".toByteArray()
        val targetData = "datadatadatadata".toByteArray()

        val cipher = CBCBlockCipher.newInstance(ARIAEngine())
        cipher.init(true, ParametersWithIV(KeyParameter(keyBytes), iv))

        val outputData = ByteArray(16)

        println(targetData.size)

        val tam = cipher.processBlock(targetData, 0, outputData, 0) //.processBlock(targetData, 0, outputData, 0)

        println(toHexString(outputData))
    }

    @Test
    fun test_padding() {
        val keyBytes = "keyskeyskeyskeys".toByteArray() // generate(128 / 8)
        val iv = "iviviviviviviviv".toByteArray()
        val targetData = "datadatadatadata".toByteArray()

        val cipher = PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(ARIAEngine()))
        cipher.init(true, ParametersWithIV(KeyParameter(keyBytes), iv))

        val outputData = ByteArray(16)

        println(targetData.size)

        val tam = cipher.doFinal(outputData, 0) //.processBlock(targetData, 0, outputData, 0)

        println(toHexString(outputData))
    }

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val aria = ARIA(128)
        val cbc = CBC(aria)
        val iv = cbc.generateIV()
        val key = aria.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}