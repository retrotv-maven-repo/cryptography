package dev.retrotv.crypto.hash

import dev.retrotv.data.utils.FileUtils
import java.io.File
import java.io.IOException

/**
 * 파일을 해시하는 인터페이스입니다.
 */
interface FileHash : BinaryHash {

    /**
     * file을 해시한 값을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 해시 값
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun hash(file: File): String = hash(FileUtils.read(file))

    /**
     * file을 해시해 해시 값을 생성한 뒤, 비교할 해시 값과의 일치 여부를 반환합니다.
     *
     * @param file 해시 할 파일
     * @param digest 비교할 해시 값
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생하면 던져짐
     */
    @Throws(IOException::class)
    fun matches(file: File, digest: String?): Boolean {
        return if (digest == null) {
            false
        } else matches(FileUtils.read(file), digest)
    }
}