package dev.retrotv.crypto.twe.des;

import dev.retrotv.crypto.exception.KeyGenerateException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static dev.retrotv.enums.CipherAlgorithm.DESOFB;

public class DESOFB extends DES implements ParameterSpecGenerator<IvParameterSpec> {
    public DESOFB() {
        this.algorithm = DESOFB;
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

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(8));
    }
}
