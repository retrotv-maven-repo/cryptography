package dev.retrotv.crypto.hash

import java.nio.charset.Charset

interface PlaintextHash : BinaryHash {

    fun hash(plaintext: CharSequence): String {
        return hash(plaintext.toString()
                             .toByteArray())
    }

    fun hash(plaintext: CharSequence, charset: Charset): String {

        /*
         * // 좀 더, 확실하게 구현하고 싶은 경우, ByteBuffer를 이용해 ByteArray(byte[])로 변환할 것!
         * val byteBuffer = Charset.forName(charset.name())
         *                         .encode(CharBuffer.wrap(plaintext))
         * val result = ByteArray(byteBuffer.remaining())
         * byteBuffer[result]
         *
         * return hash(result)
         */

        return hash(plaintext.toString()
                             .toByteArray(charset))
    }
}