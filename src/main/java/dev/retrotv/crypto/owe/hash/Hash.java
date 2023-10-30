package dev.retrotv.crypto.owe.hash;

import dev.retrotv.utils.FileReadUtil;

import lombok.NonNull;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

public abstract class Hash implements Checksum, PasswordWithSalt {

    @Override
    public String hash(@NonNull File file) throws IOException {
        return hash(FileReadUtil.read(file));
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

        return matches(FileReadUtil.read(file), checksum);
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

        byte[] file1Data = FileReadUtil.read(file1);
        byte[] file2Data = FileReadUtil.read(file2);

        return matches(file1Data, file2Data);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return hash(password.getBytes());
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset) {
        String password = String.valueOf(rawPassword);
        return hash(password.getBytes(charset));
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull CharSequence salt) {
        if ("".contentEquals(rawPassword) && "".contentEquals(salt)) {
            throw new IllegalArgumentException("rawPassword 및 salt는 빈 값일 수 없습니다.");
        }

        return encode(String.valueOf(rawPassword) + salt);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull CharSequence salt, @NonNull Charset charset) {
        if ("".contentEquals(rawPassword) && "".contentEquals(salt)) {
            return "";
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
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        if (salt == null) {
            salt = "";
        }

        return matches(String.valueOf(rawPassword) + salt, encodedPassword);
    }
}
