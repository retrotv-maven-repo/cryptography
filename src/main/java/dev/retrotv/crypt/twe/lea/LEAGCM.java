package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherModeAE;
import kr.re.nsr.crypto.symm.LEA.GCM;
import lombok.NonNull;

import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public abstract class LEAGCM extends LEA implements ParameterSpecGenerator<GCMParameterSpec> {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec iv) throws CryptFailException {
        try {
            BlockCipherModeAE cipher = new GCM();
            GCMParameterSpec gcmSpec = (GCMParameterSpec) iv;

            // GCMParameterSpec의 tLen은 bit 기준이고, taglen이 byte 크기여야 하므로 8로 나눔
            cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded(), gcmSpec.getIV(), gcmSpec.getTLen() / 8);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec iv) throws CryptFailException {
        try {
            BlockCipherModeAE cipher = new GCM();
            GCMParameterSpec gcmSpec = (GCMParameterSpec) iv;

            cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded(), gcmSpec.getIV(), gcmSpec.getTLen() / 8);

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public GCMParameterSpec generateSpec() {
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH));
    }
}
