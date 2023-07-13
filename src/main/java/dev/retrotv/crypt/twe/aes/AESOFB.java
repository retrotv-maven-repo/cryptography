package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.WrongKeyLengthException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.AESOFB;

public class AESOFB extends AES implements ParameterSpecGenerator<IvParameterSpec> {

    public AESOFB(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESOFB;
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
