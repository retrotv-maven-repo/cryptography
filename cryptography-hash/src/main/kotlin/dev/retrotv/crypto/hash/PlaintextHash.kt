package dev.retrotv.crypto.hash

import dev.retrotv.data.enums.EncodeFormat
import java.io.IOException
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
    fun hashing(plaintext: CharSequence): ByteArray = hashing(plaintext.toString().toByteArray())

    /**
     * 평문을 해시한 값을 생성하고 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @param charset 해시 할 평문의 캐릭터 셋
     * @return 해시 값
     */
    fun hashing(plaintext: CharSequence, charset: Charset): ByteArray {

        /*
         * // 좀 더, 확실하게 구현하고 싶은 경우, ByteBuffer를 이용해 ByteArray(byte[])로 변환할 것!
         * val byteBuffer = Charset.forName(charset.name())
         *                         .encode(CharBuffer.wrap(plaintext))
         * val result = ByteArray(byteBuffer.remaining())
         * byteBuffer[result]
         *
         * return hash(result)
         */

        return hashing(plaintext.toString()
                                .toByteArray(charset))
    }

    /**
     * 평문을 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @param digest 비교할 해시 값
     * @return 일치 여부
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(
        plaintext: CharSequence, digest: String?
    ): Boolean = matches(plaintext.toString().toByteArray(), digest, EncodeFormat.HEX)

    /**
     * 평문을 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     *
     * @param plaintext 해시 할 평문
     * @param digest 비교할 해시 값
     * @param encoderFormat 해시 값을 인코딩할 포맷 (기본값: HEX)
     * @return 일치 여부
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(
        plaintext: CharSequence, digest: String?, encoderFormat: EncodeFormat = EncodeFormat.HEX
    ): Boolean = matches(plaintext.toString().toByteArray(), digest, encoderFormat)
}