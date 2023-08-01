package dev.retrotv.crypto.twe.des;

import dev.retrotv.crypto.exception.KeyGenerateException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static dev.retrotv.enums.CipherAlgorithm.TRIPLE_DESCTS;

public class TripleDESCTS extends DES implements ParameterSpecGenerator<IvParameterSpec> {
    public TripleDESCTS() {
        this.algorithm = TRIPLE_DESCTS;
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
