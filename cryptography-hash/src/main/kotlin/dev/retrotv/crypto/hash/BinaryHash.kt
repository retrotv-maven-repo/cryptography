package dev.retrotv.crypto.hash

import java.io.IOException

interface BinaryHash {

    /**
     * 바이너리 데이터를 해시한 값을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 해시 값
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    fun hash(data: ByteArray): String

    /**
     * 바이너리 데이터를 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     *
     * @param file 해시 할 파일
     * @param digest 비교할 해시 값
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    fun matches(data: ByteArray, digest: String?): Boolean
}