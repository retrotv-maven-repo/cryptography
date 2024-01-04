package dev.retrotv.crypto.owe.mac

import dev.retrotv.crypto.owe.mac.sha.HMACSHA512
import dev.retrotv.data.enums.EncodeFormat
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HMACSHA512Test {

    @Test
    fun test() {
        val hmac = HMACSHA512()
        println(hmac.hash("hash".toByteArray(), "key".toByteArray()))
        assertTrue(hmac.verify("hash".toByteArray(), "key".toByteArray(), hmac.hash("hash".toByteArray(), "key".toByteArray())))

        println(hmac.hash("hash".toByteArray(), "key".toByteArray(), EncodeFormat.BASE64))
        assertTrue(
            hmac.verify(
                "hash".toByteArray(),
                "key".toByteArray(),
                hmac.hash("hash".toByteArray(), "key".toByteArray(), EncodeFormat.BASE64),
                EncodeFormat.BASE64
            )
        )
        assertFalse(
            hmac.verify(
                "hash".toByteArray(),
                "key".toByteArray(),
                hmac.hash("hash".toByteArray(), "false key".toByteArray(), EncodeFormat.BASE64),
                EncodeFormat.BASE64
            )
        )
    }
}