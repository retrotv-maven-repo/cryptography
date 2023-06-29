package dev.retrotv.crypt.twe.des;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.enums.Algorithm;

public class TripleDESCBC extends DES {
    public TripleDESCBC() {
        this.algorithm = Algorithm.TRIPLE_DESCBC_PADDING;
    }

    @Override
    public byte[] generateKey() throws KeyGenerateException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerateException("NoSuchAlgorithmException: \n지원하지 않는 암호화 알고리즘 입니다.");
        }
    }
}
