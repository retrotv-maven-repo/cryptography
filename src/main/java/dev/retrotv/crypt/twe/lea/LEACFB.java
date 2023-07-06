package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.WrongKeyLengthException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

import static dev.retrotv.enums.Algorithm.LEACFB;

public class LEACFB extends LEA implements ParameterSpecGenerator<IvParameterSpec> {

    public LEACFB(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = LEACFB;
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
