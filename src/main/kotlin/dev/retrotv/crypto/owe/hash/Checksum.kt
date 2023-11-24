package dev.retrotv.crypto.owe.hash

import dev.retrotv.data.enums.EncodeFormat

/**
 * 체크섬 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
interface Checksum {

    /**
     * data를 해시한 뒤, Hex로 인코딩 한 checksum을 반환합니다.
     *
     * @param data 해시 할 데이터
     * @return 체크섬
     */
    fun hash(data: ByteArray): String

    /**
     * data를 해시한 뒤, 지정된 encodeFormat으로 인코딩 한 checksum을 반환합니다.
     *
     * @param data 해시 할 데이터
     * @param encodeFormat 반환할 문자열의 인코딩 방식
     * @return 체크섬
     */
    fun hash(data: ByteArray, encodeFormat: EncodeFormat): String

    /**
     * data를 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data 해시 할 데이터
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     */
    fun matches(data: ByteArray, checksum: String?): Boolean {
        return if (checksum == null) {
            false
        } else checksum == hash(data)
    }

    /**
     * data1, data2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data1 기준 데이터
     * @param data2 비교할 데이터
     * @return 일치 여부
     */
    fun matches(data1: ByteArray, data2: ByteArray?): Boolean {
        return if (data2 == null) {
            false
        } else hash(data1) == hash(data2)
    }
}
