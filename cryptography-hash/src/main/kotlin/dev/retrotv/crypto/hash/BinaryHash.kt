package dev.retrotv.crypto.hash

import dev.retrotv.data.enums.EncodeFormat
import java.io.IOException

/**
 * 바이너리 데이터를 해시하는 인터페이스입니다.
 */
interface BinaryHash {

    /**
     * 바이너리 데이터를 해시한 값을 생성하고 반환합니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @return 해시 값
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun hashing(data: ByteArray): ByteArray

    /**
     * 바이너리 데이터를 해시한 값을 생성하고 반환합니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교 할 해시 값
     * @return 일치 여부
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(data: ByteArray, digest: ByteArray?): Boolean = hashing(data) == digest

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * HEX 값으로 비교하며, 대소문자를 구분하지 않습니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교할 해시 값
     * @return 일치 여부
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(data: ByteArray, digest: String?): Boolean = matches(data, digest, EncodeFormat.HEX)

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     * 대소문자를 구분하지 않습니다.
     *
     * @param data 해시 할 바이너리 데이터
     * @param digest 비교할 해시 값
     * @param encoderFormat 해시 값을 인코딩할 포맷 (기본값: HEX)
     * @return 일치 여부
     * @throws IOException 바이너리를 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(data: ByteArray, digest: String?, encoderFormat: EncodeFormat): Boolean
}