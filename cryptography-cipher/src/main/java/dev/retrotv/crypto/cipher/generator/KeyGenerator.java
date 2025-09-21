package dev.retrotv.crypto.cipher.generator;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.exception.GenerateException;
import dev.retrotv.crypto.util.RandomGenerateUtils;

public final class KeyGenerator {

    private KeyGenerator() {
        throw new UnsupportedOperationException("KeyGenerator 클래스는 인스턴스화 할 수 없습니다.");
    }

    public static byte[] generateKey(int keyLen) {
        if (keyLen != 8 && keyLen != 16 && keyLen != 24 && keyLen != 32) {
            throw new IllegalArgumentException("keyLen의 값은 8, 16, 24, 32 중 하나의 값이어야 합니다.");
        }
        return RandomGenerateUtils.generateBytes(keyLen);
    }

    public static byte[] generateKey(ECipher algorithm) throws GenerateException {
        return generateKey(algorithm, null);
    }

    public static byte[] generateKey(ECipher algorithm, Integer keyLen) throws GenerateException {
        switch (algorithm) {
            case AES:
            case ARIA:
            case LEA:
                if (keyLen == null) {
                    throw new GenerateException("keyLen 인수는 필수 입니다.");
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
