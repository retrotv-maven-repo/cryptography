package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.CryptFailException;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import kr.re.nsr.crypto.symm.LEA.ECB;
import lombok.NonNull;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public abstract class LEAECB extends LEA {

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            return encrypt(data, key);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key) throws CryptFailException {
        try {
            BlockCipherMode cipher = new ECB();
            cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded());
            cipher.setPadding(new PKCS5Padding(16));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            return decrypt(encryptedData, key);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key) throws CryptFailException {
        try {
            BlockCipherMode cipher = new ECB();
            cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded());
            cipher.setPadding(new PKCS5Padding(16));

            return cipher.doFinal(encryptedData);
        }  catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }
}
