package dev.retrotv.crypto.owe.mac

import dev.retrotv.crypto.owe.mac.md.HMACMD5
import dev.retrotv.data.enums.EncodeFormat
import kotlin.test.Test
import kotlin.test.assertTrue

class HMACMD5Test {

    @Test
    fun test() {
        val hmac = HMACMD5()
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
    }
}