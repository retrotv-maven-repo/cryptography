package dev.retrotv.crypt.owe.hash;

import java.io.File;
import java.io.IOException;

/**
 * 체크섬 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface Checksum {

    /**
     * data를 해시해 checksum을 생성하고 반환합니다.
     *
     * @param data 해시 할 데이터
     * @return 체크섬
     */
    String hash(byte[] data);

    /**
     * file을 해시해 checksum을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 체크섬
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    String hash(File file) throws IOException;

    /**
     * data를 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data 해시 할 데이터
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     */
    boolean matches(byte[] data, String checksum);

    /**
     * file을 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file 해시 할 파일
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    boolean matches(File file, String checksum) throws IOException;

    /**
     * data1, data2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data1 해시 할 데이터
     * @param data2 해시 할 데이터
     * @return 일치 여부
     */
    boolean matches(byte[] data1, byte[] data2);

    /**
     * file1, file2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file1 해시 할 파일
     * @param file2 해시 할 파일
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    boolean matches(File file1, File file2) throws IOException;
}