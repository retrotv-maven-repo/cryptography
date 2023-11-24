package dev.retrotv.crypto.owe.hash

import dev.retrotv.data.utils.read
import java.io.File
import java.io.IOException

interface FileChecksum : Checksum {

    /**
     * file을 해시해 checksum을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 체크섬
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun hash(file: File): String {
        return hash(read(file))
    }

    /**
     * file을 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file 해시 할 파일
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(file: File, checksum: String?): Boolean {
        return if (checksum == null) {
            false
        } else matches(read(file), checksum)
    }

    /**
     * file1, file2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file1 기준 파일
     * @param file2 비교할 파일
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    @Throws(IOException::class)
    fun matches(file1: File, file2: File?): Boolean {
        if (file2 == null) {
            return false
        }

        val file1Data = read(file1)
        val file2Data = read(file2)
        return matches(file1Data, file2Data)
    }
}