package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.CryptoFailException;
import dev.retrotv.crypt.exception.WrongKeyLengthException;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import kr.re.nsr.crypto.symm.LEA.ECB;
import lombok.NonNull;

import java.security.Key;

import static dev.retrotv.enums.CipherAlgorithm.LEAECB;

public class LEAECB extends LEA {

    public LEAECB(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = LEAECB;
    }

    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key) throws CryptoFailException {
        try {
            BlockCipherMode cipher = new ECB();
            cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded());
            cipher.setPadding(new PKCS5Padding(16));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }

    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key) throws CryptoFailException {
        try {
            BlockCipherMode cipher = new ECB();
            cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded());
            cipher.setPadding(new PKCS5Padding(16));

            return cipher.doFinal(encryptedData);
        }  catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }
}
