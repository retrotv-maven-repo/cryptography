package dev.retrotv.crypt.twe.aes;

import java.security.SecureRandom;

public abstract class AESGCM extends AES {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;
    
    public byte[] generateIV() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        sr.nextBytes(iv);

        return iv;
    }
}
