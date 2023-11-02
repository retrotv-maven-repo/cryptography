package dev.retrotv.crypto.owe.hash;

import dev.retrotv.data.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

public abstract class Hash implements Checksum, PasswordWithSalt {

    @Override
    public String hash(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("file은 null일 수 없습니다.");
        }

        return hash(FileUtils.read(file));
    }

    @Override
    public boolean matches(byte[] data, String checksum) {
        if (data == null || checksum == null) {
            return false;
        }

        return checksum.equals(hash(data));
    }

    @Override
    public boolean matches(File file, String checksum) throws IOException {
        if (file == null || checksum == null) {
            return false;
        }

        return matches(FileUtils.read(file), checksum);
    }

    @Override
    public boolean matches(byte[] data1, byte[] data2) {
        if (data1 == null || data2 == null) {
            return false;
        }

        return hash(data1).equals(hash(data2));
    }

    @Override
    public boolean matches(File file1, File file2) throws IOException {
        if (file1 == null || file2 == null) {
            return false;
        }

        byte[] file1Data = FileUtils.read(file1);
        byte[] file2Data = FileUtils.read(file2);

        return matches(file1Data, file2Data);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword은 null일 수 없습니다.");
        }

        String password = String.valueOf(rawPassword);
        return hash(password.getBytes());
    }

    @Override
    public String encode(CharSequence rawPassword, Charset charset) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword은 null일 수 없습니다.");
        }

        if (charset == null) {
            throw new IllegalArgumentException("charset은 null일 수 없습니다.");
        }

        String password = String.valueOf(rawPassword);
        return hash(password.getBytes(charset));
    }

    @Override
    public String encode(CharSequence rawPassword, CharSequence salt) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword는 null일 수 없습니다.");
        }

        if (salt == null) {
            throw new IllegalArgumentException("salt는 null일 수 없습니다.");
        }

        return encode(String.valueOf(rawPassword) + salt);
    }

    @Override
    public String encode(CharSequence rawPassword, CharSequence salt, Charset charset) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword는 null일 수 없습니다.");
        }

        if (salt == null) {
            throw new IllegalArgumentException("salt는 null일 수 없습니다.");
        }

        return encode(String.valueOf(rawPassword) + salt, charset);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        return encodedPassword.equals(encode(String.valueOf(rawPassword)));
    }

    @Override
    public boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null || salt == null || encodedPassword == null) {
            return false;
        }

        return matches(String.valueOf(rawPassword) + salt, encodedPassword);
    }
}
