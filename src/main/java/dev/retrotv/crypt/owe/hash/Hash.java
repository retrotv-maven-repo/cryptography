package dev.retrotv.crypt.owe.hash;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;
import dev.retrotv.utils.FileReadUtil;
import lombok.NonNull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

public abstract class Hash implements Checksum, PasswordWithSalt {
    protected static final Logger log = LogManager.getLogger();

    @Override
    public String hash(File file) throws IOException {
        return hash(FileReadUtil.read(file));
    }

    @Override
    public boolean matches(byte[] data, String checksum) {
        if (data == null) {
            log.warn("매개변수 data가 null 입니다.");
            return false;
        }

        if (checksum == null) {
            log.warn("매개변수 checksum이 null 입니다.");
            return false;
        }

        return checksum.equals(hash(data));
    }

    @Override
    public boolean matches(File file, String checksum) throws IOException {
        if (file == null) {
            log.warn("매개변수 file이 null 입니다.");
            return false;
        }

        if (checksum == null) {
            log.warn("매개변수 checksum이 null 입니다.");
            return false;
        }

        return matches(FileReadUtil.read(file), checksum);
    }

    @Override
    public boolean matches(byte[] data1, byte[] data2) {
        if (data1 == null) {
            log.warn("매개변수 data1이 null 입니다.");
            return false;
        }

        if (data2 == null) {
            log.warn("매개변수 data2가 null 입니다.");
            return false;
        }

        return hash(data1).equals(hash(data2));
    }

    @Override
    public boolean matches(File file1, File file2) throws IOException {
        if (file1 == null) {
            log.warn("매개변수 file1이 null 입니다.");
            return false;
        }

        if (file2 == null) {
            log.warn("매개변수 file2가 null 입니다.");
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
    public String encode(@NonNull CharSequence rawPassword, CharSequence salt) {
        if (salt == null) {
            log.warn("매개변수 salt가 null 입니다.");
            log.warn("의도한 것이 아니라면 encode(CharSequence rawPassword) 메소드를 사용하십시오.");
        }

        return encode(String.valueOf(rawPassword) + salt);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, CharSequence salt, Charset charset) {
        if (salt == null) {
            log.warn("매개변수 salt가 null 입니다.");
            log.warn("의도한 것이 아니라면 encode(CharSequence rawPassword) 메소드를 사용하십시오.");
        }

        return encode(String.valueOf(rawPassword) + salt, charset);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            log.warn("매개변수 rawPassword가 null 입니다.");
            return false;
        }

        if (encodedPassword == null) {
            log.warn("매개변수 encodedPassword가 null 입니다.");
            return false;
        }

        return encodedPassword.equals(encode(String.valueOf(rawPassword)));
    }

    @Override
    public boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null) {
            log.warn("매개변수 rawPassword가 null 입니다.");
            return false;
        }

        if (encodedPassword == null) {
            log.warn("매개변수 encodedPassword가 null 입니다.");
            return false;
        }

        if (salt == null) {
            log.warn("매개변수 salt가 null 입니다.");
            log.warn("의도한 것이 아니라면 matches(CharSequence rawPassword, String encodedPassword) 메소드를 사용하십시오.");
        }

        return matches(String.valueOf(rawPassword) + salt, encodedPassword);
    }

    @Override
    public String generateSalt() {
        RandomValue rv = new RandomValue();
        rv.generate();
        return rv.getValue();
    }

    @Override
    public String generateSalt(int len) {
        RandomValue rv = new RandomValue();
        rv.generate(len);
        return rv.getValue();
    }

    @Override
    public String generateSalt(SecurityStrength securityStrength) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength);
        return rv.getValue();
    }

    @Override
    public String generateSalt(SecurityStrength securityStrength, int len) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength, len);
        return rv.getValue();
    }
}
