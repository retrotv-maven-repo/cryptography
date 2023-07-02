package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

public abstract class AESOFB extends AES implements ParameterSpecGenerator<IvParameterSpec> {

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
