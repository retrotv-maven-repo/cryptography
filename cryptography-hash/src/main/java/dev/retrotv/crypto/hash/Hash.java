package dev.retrotv.crypto.hash;

import dev.retrotv.crypto.exception.AlgorithmNotFoundException;
import dev.retrotv.crypto.hash.enums.EHash;
import dev.retrotv.crypto.hash.util.MessageDigestUtils;
import dev.retrotv.data.enums.EncodeFormat;
import dev.retrotv.data.utils.ByteUtils;
import lombok.NonNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * 해시 알고리즘 클래스 구현을 위한 클래스입니다.
 * BinaryHash, PlaintextHash 인터페이스를 구현합니다.
 */
public class Hash implements PlaintextHash {
    private static final Logger log = LoggerFactory.getLogger(Hash.class);
    private EHash algorithm;

    private static Hash instance;

    private Hash() {}

    /**
     * 지정된 해시 알고리즘 인스턴스를 반환합니다.
     *
     * @param algorithm 해시 알고리즘
     * @return 해시 인스턴스
     */
    public static synchronized Hash getInstance(@NonNull EHash algorithm) {
        if (instance != null && !Objects.equals(instance.algorithm, algorithm)) {
            instance = null;
        }

        synchronized (Hash.class) {
            if (instance == null) {
                instance = new Hash();
                instance.algorithm = algorithm;
            }
        }

        return instance;
    }

    /**
     * 지정된 해시 알고리즘 인스턴스를 반환합니다.
     *
     * @param algorithm 해시 알고리즘
     * @return 해시 인스턴스
     * @throws AlgorithmNotFoundException 지원하지 않는 알고리즘일 경우 던짐
     */
    public static Hash getInstance(@NonNull String algorithm) {
        try {
            // .valueOf()는 해당하는 enum이 없으면 IllegalArgumentException을 던짐
            return getInstance(EHash.valueOf(algorithm.toUpperCase()));
        } catch (IllegalArgumentException ex) {
            throw new AlgorithmNotFoundException("지원하지 않는 알고리즘 입니다.", ex);
        }
    }

    @Override
    public byte[] hashing(@NonNull byte[] data) {
        log.debug("선택된 해시 알고리즘: {}", algorithm.label());

        if (algorithm != EHash.CRC32) {
            return MessageDigestUtils.hashing(algorithm, data);
        } else {
            // CRC32 해시 알고리즘은 마지막 4바이트 해시 값을 반환함
            byte[] hashedData = MessageDigestUtils.hashing(algorithm, data);
            byte[] crc32 = new byte[4];
            System.arraycopy(hashedData, 4, crc32, 0, 4);
            return crc32;
        }
    }

    @Override
    public boolean matches(@NonNull byte[] data, String digest, EncodeFormat encoderFormat) {
        if (encoderFormat == null) {
            log.debug("encoderFormat이 null 입니다. 기본값 HEX로 설정합니다.");
            encoderFormat = EncodeFormat.HEX;
        }
        
        log.debug("인코딩 포맷 유형: {}", encoderFormat.name());

        if (digest == null) {
            log.warn("digest가 null 입니다.");
            return false;
        }

        String encodedData = ByteUtils.toHexString(hashing(data));
        return encodedData.equalsIgnoreCase(digest);
    }
}
