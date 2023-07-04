package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import kr.re.nsr.crypto.symm.LEA.CFB;
import lombok.NonNull;

import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public abstract class LEACFB extends LEA implements ParameterSpecGenerator<IvParameterSpec> {

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            BlockCipherMode cipher = new CFB();
            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded(), ivSpec.getIV());

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        try {
            BlockCipherMode cipher = new CFB();
            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded(), ivSpec.getIV());

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
