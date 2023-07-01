package dev.retrotv.crypt.twe.des;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.SecureRandomUtil;

public class TripleDESCBC extends DES implements ParameterSpecGenerator<IvParameterSpec> {
    public TripleDESCBC() {
        this.algorithm = Algorithm.TRIPLE_DESCBC_PADDING;
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

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(8));
    }
}