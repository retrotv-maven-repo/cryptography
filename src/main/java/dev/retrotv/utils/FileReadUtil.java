package dev.retrotv.utils;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileReadUtil {
    private static final CommonMessageUtil COMMON_MESSAGE = new CommonMessageUtil();

    public static byte[] read(File file) throws IOException {
        byte[] fileData;

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(file.toPath()))) {
            fileData = new byte[(int) file.length()];
            dis.readFully(fileData);
        } catch (IOException e) {
            throw new IOException(COMMON_MESSAGE.getMessage("exception.fileRead"));
        }

        return fileData;
    }
}
