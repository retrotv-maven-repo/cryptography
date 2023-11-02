package dev.retrotv.crypto.twe.aes;

import dev.retrotv.crypto.exception.WrongKeyLengthException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.AESCTS;

public class AESCTS extends AES implements ParameterSpecGenerator<IvParameterSpec> {

    public AESCTS(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESCTS;
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
