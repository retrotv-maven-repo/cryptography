package dev.retrotv.crypto.twe.des;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;

import dev.retrotv.crypto.exception.KeyGenerateException;

import static dev.retrotv.enums.CipherAlgorithm.TRIPLE_DESECB;

public class TripleDESECB extends DES {
    public TripleDESECB() {
        this.algorithm = TRIPLE_DESECB;
    }

    @Override
    public Key generateKey() throws KeyGenerateException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.");
        }
    }
}
