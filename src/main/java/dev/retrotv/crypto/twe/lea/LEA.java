package dev.retrotv.crypto.twe.lea;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.twe.KeyGenerator;
import dev.retrotv.crypto.twe.TwoWayEncryption;
import dev.retrotv.enums.CipherAlgorithm;
import dev.retrotv.enums.Padding;
import dev.retrotv.utils.SecureRandomUtil;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipherMode;
import kr.re.nsr.crypto.padding.PKCS5Padding;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import static dev.retrotv.enums.Padding.*;
import static dev.retrotv.enums.CipherAlgorithm.LEAECB;

public abstract class LEA implements TwoWayEncryption, KeyGenerator {
    protected static final Logger log = LogManager.getLogger();

    protected int keyLen;
    protected CipherAlgorithm algorithm;
    protected Padding padding = NO_PADDING;

    @Override
    public byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec spec) {
        log.debug("선택된 알고리즘: {}", algorithm.label() + "/" + padding.label());

        if (algorithm == LEAECB && data.length > keyLen) {
            log.info("ECB 블록암호 운영모드는 대용량 데이터를 처리하는데 적합하지 않습니다.");
        }

        if (padding == PKCS5_PADDING) {
            log.info("PKCS#5 Padding 기법은 오라클 패딩 공격에 취약합니다.");
            log.info("호환성이 목적이 아니라면, 보안을 위해 패딩이 불필요한 블록 암호화 운영모드 사용을 고려하십시오.");
        }

        try {
            BlockCipherMode cipher = getCipherMode(algorithm);
            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            if (algorithm == LEAECB) {
                cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded());
            } else {
                cipher.init(BlockCipher.Mode.ENCRYPT, key.getEncoded(), ivSpec.getIV());
            }

            if (padding == PKCS5_PADDING) {
                cipher.setPadding(new PKCS5Padding(16));
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, Key key, AlgorithmParameterSpec spec) {
        log.debug("선택된 알고리즘: {}", algorithm.label() + "/" + padding.label());

        try {
            BlockCipherMode cipher = getCipherMode(algorithm);
            IvParameterSpec ivSpec = (IvParameterSpec) spec;

            if (algorithm == LEAECB) {
                cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded());
            } else {
                cipher.init(BlockCipher.Mode.DECRYPT, key.getEncoded(), ivSpec.getIV());
            }

            if (padding == PKCS5_PADDING) {
                cipher.setPadding(new PKCS5Padding(16));
            }

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new CryptoFailException(e.getMessage(), e);
        }
    }

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    public void dataPadding() {
        padding = PKCS5_PADDING;
    }

    @Override
    public Key generateKey() {
        return new SecretKeySpec(SecureRandomUtil.generate(keyLen / 8), "LEA");
    }

    private BlockCipherMode getCipherMode(CipherAlgorithm algorithm) throws NoSuchAlgorithmException {
        BlockCipherMode cipher;

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

        return cipher;
    }
}
