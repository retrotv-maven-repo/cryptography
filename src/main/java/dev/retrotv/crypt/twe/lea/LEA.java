package dev.retrotv.crypt.twe.lea;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.twe.KeyGenerator;
import dev.retrotv.crypt.twe.TwoWayEncryption;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.enums.Padding;
import dev.retrotv.utils.SecureRandomUtil;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.padding.PKCS5Padding;
import lombok.NonNull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.Padding.*;
import static dev.retrotv.enums.Algorithm.LEAECB;

public abstract class LEA implements TwoWayEncryption, KeyGenerator {
    protected static final Logger log = LogManager.getLogger();

    protected int keyLen;
    protected Algorithm algorithm;
    protected Padding padding = NO_PADDING;

    @Override
    public byte[] encrypt(@NonNull byte[] data, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        log.debug("선택된 알고리즘: {}", algorithm.label() + "/" + padding.label());
        BlockCipherMode cipher;

        try {
            switch (algorithm) {
                case LEACBC:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CBC();
                    break;
                case LEACFB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CFB();
                    break;
                case LEACTR:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CTR();
                    break;
                case LEAECB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.ECB();
                    break;
                case LEAOFB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.OFB();
                    break;
                default:
                    throw new NoSuchAlgorithmException("지원하지 않는 알고리즘 입니다.");
            }

            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            if (algorithm == LEAECB) {
                cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded());
            } else {
                cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded(), ivSpec.getIV());
            }

            if (padding == PADDING) {
                cipher.setPadding(new PKCS5Padding(16));
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @NonNull Key key, AlgorithmParameterSpec spec) throws CryptFailException {
        log.debug("선택된 알고리즘: {}", algorithm.label() + "/" + padding.label());
        BlockCipherMode cipher;

        try {
            switch (algorithm) {
                case LEACBC:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CBC();
                    break;
                case LEACFB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CFB();
                    break;
                case LEACTR:
                    cipher = new kr.re.nsr.crypto.symm.LEA.CTR();
                    break;
                case LEAECB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.ECB();
                    break;
                case LEAOFB:
                    cipher = new kr.re.nsr.crypto.symm.LEA.OFB();
                    break;
                default:
                    throw new NoSuchAlgorithmException("지원하지 않는 알고리즘 입니다.");
            }

            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            if (algorithm == LEAECB) {
                cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded());
            } else {
                cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded(), ivSpec.getIV());
            }

            if (padding == PADDING) {
                cipher.setPadding(new PKCS5Padding(16));
            }

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptFailException(e.getMessage(), e);
        }
    }

    public void dataPadding() {
        padding = PADDING;
    }

    @Override
    public Key generateKey() {
        return new SecretKeySpec(SecureRandomUtil.generate(keyLen / 8), "LEA");
    }
}
