package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.twe.ParamsWithIV
import dev.retrotv.crypto.twe.mode.CBC
import dev.retrotv.data.utils.toHexString
import org.bouncycastle.crypto.engines.ARIAEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import kotlin.test.Test

class AESTest {

    @Test
    fun test_default() {
        val message = "The lazy dog jumps over the brown fox!"
        val aes = AES(128)
        val cbc = CBC(aes)
        val iv = cbc.generateIV()
        val key = aes.generateKey()

        val encryptedResult = cbc.encrypt(message.toByteArray(), ParamsWithIV(key, iv))
        val originalResult = cbc.decrypt(encryptedResult.data, ParamsWithIV(key, iv))

        println(String(originalResult.data))
    }
}