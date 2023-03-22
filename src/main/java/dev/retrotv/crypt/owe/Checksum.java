package dev.retrotv.crypt.owe;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public interface Checksum {

    String encode(byte[] data);

    default boolean matches(byte[] data, String checksum) {
        if (data == null || checksum == null) {
            throw new NullPointerException("비교할 data 혹은 checksum 값이 null 입니다.");
        }

        return checksum.equals(encode(data));
    }

    default boolean matches(File file, String checksum) throws IOException {
        if (file == null || checksum == null) {
            throw new NullPointerException("비교할 file 혹은 checksum 값이 null 입니다.");
        }

        byte[] fileData;

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            fileData = new byte[(int) file.length()];
            dis.readFully(fileData);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }

        return matches(fileData, checksum);
    }

    default boolean matches(byte[] data1, byte[] data2) {
        if (data1 == null || data2 == null) {
            throw new NullPointerException("비교할 데이터가 null 입니다.");
        }

        return encode(data1).equals(encode(data2));
    }

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
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file2.toPath()))) {
            file2Data = new byte[(int) file2.length()];
            dis.readFully(file2Data);
        } catch (IOException e) {
            throw new IOException("파일을 읽어들이는 과정에서 예상치 못한 오류가 발생했습니다.");
        }

        return matches(file1Data, file2Data);
    }
}
