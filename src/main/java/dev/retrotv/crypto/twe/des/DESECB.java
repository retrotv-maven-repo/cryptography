package dev.retrotv.crypto.twe.des;

import dev.retrotv.crypto.exception.KeyGenerateException;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static dev.retrotv.enums.CipherAlgorithm.DESECB;

public class DESECB extends DES {
    public DESECB() {
        this.algorithm = DESECB;
    }

    @Override
    public Key generateKey() throws KeyGenerateException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.");
        }
    }
}
