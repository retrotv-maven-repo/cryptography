package dev.retrotv.crypto.hash

import java.nio.charset.Charset

/**
 * 평문을 해시하는 인터페이스입니다.
 */
interface PlaintextHash : BinaryHash {

    /**
     * 평문을 해시한 값을 생성하고 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @return 해시 값
     */
    fun hash(plaintext: CharSequence): String {
        return hash(plaintext.toString()
                             .toByteArray())
    }

    /**
     * 평문을 해시한 값을 생성하고 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @param charset 해시 할 평문의 캐릭터 셋
     * @return 해시 값
     */
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