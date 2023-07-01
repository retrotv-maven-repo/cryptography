package dev.retrotv.crypt.owe;

import dev.retrotv.enums.Algorithm;
import lombok.NonNull;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public abstract class MessageDigestEncode implements Checksum, PasswordWithSalt {
    protected static final Logger log = LogManager.getLogger();

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    protected byte[] encode(@NonNull Algorithm algorithm, @NonNull byte[] data) {
        try {
            String algorithmName = algorithm.label();
            log.debug("알고리즘: {}", algorithmName);
            
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { return new byte[0]; }
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
}
