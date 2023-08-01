package dev.retrotv.crypto.twe.lea;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.exception.WrongKeyLengthException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherModeAE;
import kr.re.nsr.crypto.symm.LEA.GCM;
import lombok.NonNull;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.LEAGCM;

public class LEAGCM extends LEA implements ParameterSpecGenerator<GCMParameterSpec> {
    protected static final int GCM_IV_LENGTH = 12;
    protected static final int GCM_TAG_LENGTH = 16;
    protected String aad = null;

    public LEAGCM(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = LEAGCM;
    }

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptoFailException {
        try {
            BlockCipherModeAE cipher = new GCM();
            GCMParameterSpec gcmSpec = (GCMParameterSpec) spec;

            // GCMParameterSpec의 tLen은 bit 기준이고, taglen이 byte 크기여야 하므로 8로 나눔
            cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded(), gcmSpec.getIV(), gcmSpec.getTLen() / 8);
            if (aad != null) { cipher.updateAAD(aad.getBytes()); }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptoFailException {
        try {
            BlockCipherModeAE cipher = new GCM();
            GCMParameterSpec gcmSpec = (GCMParameterSpec) spec;

            cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded(), gcmSpec.getIV(), gcmSpec.getTLen() / 8);
            if (aad != null) { cipher.updateAAD(aad.getBytes()); }

            byte[] originalData = cipher.doFinal(encryptedData);
            if (originalData == null) {
                throw new AEADBadTagException("동일한 Tag를 사용해 복호화를 시도했는지 확인 하십시오.");
            }

            return originalData;
        } catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }

    @Override
    public GCMParameterSpec generateSpec() {
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH));
    }

    public void updateAAD(String aad) {
        this.aad = aad;
    }
}
