package dev.retrotv.crypto.cipher.generator;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.exception.GenerateException;
import dev.retrotv.crypto.util.RandomGenerateUtils;

/**
 * 암호화 키를 생성하기 위한 유틸리티 클래스입니다.
 */
public final class KeyGenerator {
    private KeyGenerator() {
        throw new UnsupportedOperationException("KeyGenerator 클래스는 인스턴스화 할 수 없습니다.");
    }

    /**
     * 지정된 길이의 암호화 키를 생성합니다.
     *
     * @param keyLen 생성할 키의 길이 (8, 16, 24, 32 중 하나)
     * @return 생성된 키 바이트 배열
     * @throws IllegalArgumentException keyLen이 8, 16, 24, 32 중 하나가 아닌 경우 던져짐
     */
    public static byte[] generateKey(int keyLen) {
        if (keyLen != 8 && keyLen != 16 && keyLen != 24 && keyLen != 32) {
            throw new IllegalArgumentException("keyLen의 값은 8, 16, 24, 32 중 하나의 값이어야 합니다.");
        }
        return RandomGenerateUtils.generateBytes(keyLen);
    }

    /**
     * 지정된 알고리즘과 키 길이에 따라 암호화 키를 생성합니다.
     *
     * @param algorithm 암호화 알고리즘 (AES, DES, TRIPLE_DES, ARIA, LEA, SEED)
     * @param keyLen AES, ARIA, LEA 알고리즘에 대해 생성할 키의 길이 (8, 16, 24, 32 중 하나). DES, TRIPLE_DES, SEED 알고리즘의 경우 해당 값은 무시됨
     * @return 생성된 키 바이트 배열
     * @throws GenerateException 지원하지 않는 알고리즘이거나 keyLen이 필요한데 제공되지 않은 경우 던져짐
     * @throws IllegalArgumentException keyLen이 8, 16, 24, 32 중 하나가 아닌 경우 던져짐 (AES, ARIA, LEA 알고리즘만 해당함)
     */
    public static byte[] generateKey(ECipher algorithm, Integer keyLen) throws GenerateException {
        switch (algorithm) {
            case AES:
            case ARIA:
            case LEA:
                if (keyLen == null) {
                    throw new GenerateException("keyLen 인수는 필수 입니다.");
                }

                if (keyLen != 8 && keyLen != 16 && keyLen != 24 && keyLen != 32) {
                    throw new IllegalArgumentException("keyLen의 값은 8, 16, 24, 32 중 하나의 값이어야 합니다.");
                }

                return generateKey(keyLen);
            case DES:
            case TRIPLE_DES:
                return generateKey(8);
            case SEED:
                return generateKey(16);
            default:
                throw new GenerateException("지원하지 않는 알고리즘 입니다.");
        }
    }
}
