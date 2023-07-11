package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.exception.WrongKeyLengthException;
import dev.retrotv.crypt.twe.KeyPairGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RSAKeyPairGenerator implements KeyPairGenerator {
    private static final Logger log = LogManager.getLogger();

    private final int keyLen;

    private static final String NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE =
            "NoSuchAlgorithmException: "
          + "\n지원하지 않는 암호화 알고리즘 입니다.";

    public RSAKeyPairGenerator(int keyLen) {
        if (keyLen != 1024 && keyLen != 2048) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        if (keyLen == 1024) {
            log.info("key 길이는 2048bit 이상을 권장합니다.");
        }

        this.keyLen = keyLen;
    }

    @Override
    public KeyPair generateKeyPair() throws KeyGenerateException {
        try {
            java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLen, new SecureRandom());

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException(NO_SUCH_ALGORITHM_EXCEPTION_MESSAGE, e);
        }
    }
}
