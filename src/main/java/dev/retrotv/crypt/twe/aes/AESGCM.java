package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.GCMParameterSpec;

public abstract class AESGCM extends AES implements ParameterSpecGenerator<GCMParameterSpec> {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;

    @Override
    public GCMParameterSpec generateSpec() {
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH));
    }
}
