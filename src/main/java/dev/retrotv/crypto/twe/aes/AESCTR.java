package dev.retrotv.crypto.twe.aes;

import dev.retrotv.crypto.exception.WrongKeyLengthException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.AESCTR;

public class AESCTR extends AES implements ParameterSpecGenerator<IvParameterSpec> {

    public AESCTR(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESCTR;
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
