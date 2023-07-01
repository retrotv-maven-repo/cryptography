package dev.retrotv.crypt.twe.des;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.enums.Algorithm;

public class DESECB extends DES {
    public DESECB() {
        this.algorithm = Algorithm.DESECB_PADDING;
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