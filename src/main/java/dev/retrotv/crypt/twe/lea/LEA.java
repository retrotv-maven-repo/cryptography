package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.twe.KeyGenerator;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.SecureRandomUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public abstract class LEA implements TwoWayEncryption, KeyGenerator {
    protected static final Logger log = LogManager.getLogger();

    protected int keyLength;
    protected Algorithm algorithm;

    @Override
    public Key generateKey() {
        return new SecretKeySpec(SecureRandomUtil.generate(keyLength), "AES");
    }
}
