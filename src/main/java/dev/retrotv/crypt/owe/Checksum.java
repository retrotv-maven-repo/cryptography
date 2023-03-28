package dev.retrotv.crypt.owe;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

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
    String encode(byte[] data);

    /**
     * file을 해시해 checksum을 생성하고 반환합니다.
     *
     * @param file 해시 할 파일
     * @return 체크섬
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default String encode(File file) throws IOException {
        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            byte[] fileData = new byte[(int) file.length()];
            dis.readFully(fileData);

            return encode(fileData);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 오류가 발생했습니다.", e);
        }
    }

    /**
     * data를 해시해 체크섬을 생성한 뒤, 비교할 checksum과 일치하는지 확인하고 일치 여부를 반환합니다.
     *
     * @param data 해시 할 데이터
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     */
    default boolean matches(byte[] data, String checksum) {
        if (data == null || checksum == null) {
            throw new NullPointerException("비교할 data 혹은 checksum 값이 null 입니다.");
        }

        return checksum.equals(encode(data));
    }

    /**
     *
     * @param file 해시 할 파일
     * @param checksum 비교할 체크섬
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default boolean matches(File file, String checksum) throws IOException {
        if (file == null || checksum == null) {
            throw new NullPointerException("비교할 file 혹은 checksum 값이 null 입니다.");
        }

        byte[] fileData;

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            fileData = new byte[(int) file.length()];
            dis.readFully(fileData);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 오류가 발생했습니다.");
        }

        return matches(fileData, checksum);
    }

    /**
     *
     * @param data1 해시 할 데이터
     * @param data2 해시 할 데이터
     * @return 일치 여부
     */
    default boolean matches(byte[] data1, byte[] data2) {
        if (data1 == null || data2 == null) {
            throw new NullPointerException("비교할 데이터가 null 입니다.");
        }

        return encode(data1).equals(encode(data2));
    }

    /**
     *
     * @param file1 해시 할 파일
     * @param file2 해시 할 파일
     * @return 일치 여부
     * @throws IOException 파일을 읽어들이는 과정에서 오류가 발생할 경우 던짐
     */
    default boolean matches(File file1, File file2) throws IOException {
        if (file1 == null || file2 == null) {
            throw new NullPointerException("비교할 파일이 null 입니다.");
        }

        byte[] file1Data;
        byte[] file2Data;

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file1.toPath()))) {
            file1Data = new byte[(int) file1.length()];
            dis.readFully(file1Data);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 오류가 발생했습니다.");
        }

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file2.toPath()))) {
            file2Data = new byte[(int) file2.length()];
            dis.readFully(file2Data);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 오류가 발생했습니다.");
        }

        return matches(file1Data, file2Data);
    }
}
