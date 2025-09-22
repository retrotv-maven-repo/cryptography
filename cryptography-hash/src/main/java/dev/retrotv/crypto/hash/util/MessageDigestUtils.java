package dev.retrotv.crypto.hash.util;

import dev.retrotv.crypto.exception.CryptoFailException;
import dev.retrotv.crypto.hash.enums.EHash;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;

public class MessageDigestUtils {
    private static final Logger log = LoggerFactory.getLogger(MessageDigestUtils.class);

    private MessageDigestUtils() {
        throw new UnsupportedOperationException("MessageDigestUtils 클래스는 인스턴스화 할 수 없습니다.");
    }

    /**
     * 지정된 EHash 유형으로 데이터를 해시하고, 해시된 데이터를 반환합니다.
     *
     * @param algorithm 암호화 시 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    public static byte[] hashing(EHash algorithm, byte[] data) {
        switch (algorithm) {
            case CRC32:
                return digestCRC32(data);
            case MD2:
            case MD5:
            case SHA1:
            case SHA224:
            case SHA256:
            case SHA384:
            case SHA512:
            case SHA512224:
            case SHA512256: {
                String algorithmName = algorithm.label();
                log.debug("알고리즘: {}", algorithmName);

                try {
                    MessageDigest md = MessageDigest.getInstance(algorithmName);
                    md.update(data);
                    return md.digest();
                } catch (NoSuchAlgorithmException ex) {
                    throw new CryptoFailException("지원하지 않는 해시 알고리즘 입니다. 알고리즘 명: " + algorithmName, ex);
                }
            }

            case SHA3224: {
                SHA3.DigestSHA3 md = new SHA3.DigestSHA3(224);
                md.update(data);
                return md.digest();
            }

            case SHA3256: {
                SHA3.DigestSHA3 md = new SHA3.DigestSHA3(256);
                md.update(data);
                return md.digest();
            }

            case SHA3384: {
                SHA3.DigestSHA3 md = new SHA3.DigestSHA3(384);
                md.update(data);
                return md.digest();
            }

            case SHA3512: {
                SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
                md.update(data);
                return md.digest();
            }

            default:
                throw new IllegalArgumentException("지원하지 않는 해시 알고리즘: " + algorithm);
        }
    }

    // CRC-32 알고리즘만 별도로 해시 로직을 사용
    private static byte[] digestCRC32(byte[] data) {
        CRC32 crc32 = new CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        return buffer.array();
    }
}
