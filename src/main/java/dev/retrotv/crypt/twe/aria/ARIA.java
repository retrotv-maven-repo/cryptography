package dev.retrotv.crypt.twe.aria;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.exception.KeyGenerateException;
import dev.retrotv.crypt.twe.KeyGenerator;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.SecureRandomUtil;
import lombok.NonNull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public abstract class ARIA implements TwoWayEncryption, KeyGenerator {
    protected static final Logger log = LogManager.getLogger();

    protected int keyLength;
    protected Algorithm algorithm;

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec iv) throws CryptFailException {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec iv) throws CryptFailException {
        return new byte[0];
    }

    @Override
    public Key generateKey() throws KeyGenerateException {
        return new SecretKeySpec(SecureRandomUtil.generate(keyLength), algorithm.label());
    }
}
