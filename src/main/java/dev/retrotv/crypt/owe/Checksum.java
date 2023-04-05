package dev.retrotv.crypt.owe;

import dev.retrotv.util.CommonMessage;
import dev.retrotv.util.FileReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;

/**
 * 체크섬 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface Checksum {
    Logger logger = LogManager.getLogger();
    CommonMessage commonMessage = new CommonMessage();

    /**
     * data를 해시해 checksum을 생성하고 반환합니다.
     *
     * @param data 해시 할 데이터
     * @return 체크섬
     */
    String encode(byte[] data);

    /**
     * file을 해시해 checksum을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 체크섬
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default String encode(File file) throws IOException {
        return encode(FileReader.read(file));
    }

    /**
     * data를 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data 해시 할 데이터
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     */
    default boolean matches(byte[] data, String checksum) {
        if (data == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "data"));
            return false;
        }

        if (checksum == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "checksum"));
            return false;
        }

        return checksum.equals(encode(data));
    }

    /**
     * file을 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file 해시 할 파일
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default boolean matches(File file, String checksum) throws IOException {
        if (file == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "file"));
            return false;
        }

        if (checksum == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "checksum"));
            return false;
        }

        return matches(FileReader.read(file), checksum);
    }

    /**
     * data1, data2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data1 해시 할 데이터
     * @param data2 해시 할 데이터
     * @return 일치 여부
     */
    default boolean matches(byte[] data1, byte[] data2) {
        if (data1 == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "data1"));
            return false;
        }

        if (data2 == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "data2"));
            return false;
        }

        return encode(data1).equals(encode(data2));
    }

    /**
     * file1, file2를 해시해 체크섬을 생성한 뒤, 두 체크섬이 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param file1 해시 할 파일
     * @param file2 해시 할 파일
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default boolean matches(File file1, File file2) throws IOException {
        if (file1 == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "file1"));
            return false;
        }

        if (file2 == null) {
            logger.warn(commonMessage.getMessage("warn.parameter.null", "file2"));
            return false;
        }

        byte[] file1Data = FileReader.read(file1);
        byte[] file2Data = FileReader.read(file2);

        return matches(file1Data, file2Data);
    }
}
