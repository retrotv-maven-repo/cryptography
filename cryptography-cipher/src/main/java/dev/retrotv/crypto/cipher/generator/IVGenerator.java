package dev.retrotv.crypto.cipher.generator;

import dev.retrotv.crypto.cipher.enums.ECipher;
import dev.retrotv.crypto.cipher.enums.EMode;
import dev.retrotv.crypto.exception.GenerateException;
import dev.retrotv.crypto.util.RandomGenerateUtils;

public final class IVGenerator {
    private IVGenerator() {
        throw new UnsupportedOperationException("IVGenerator 클래스는 인스턴스화할 수 없습니다.");
    }

    public static byte[] generateIV(int ivLen) {
        if (ivLen < 7 || ivLen > 16) {
            throw new IllegalArgumentException("ivLen의 값은 7 ~ 16 사이의 값이어야 합니다.");
        }
        return RandomGenerateUtils.generateBytes(ivLen);
    }

    public static byte[] generateIV(ECipher algorithm, EMode mode) throws GenerateException {
        switch (mode) {
            case ECB:
                throw new GenerateException("ECB 모드에서는 IV가 필요하지 않습니다.");
            case CBC:
            case CFB:
            case OFB:
            case CTR:
            case CTS:
                switch (algorithm) {
                    case AES:
                    case ARIA:
                    case LEA:
                    case SEED:
                    case SERPENT:
                        return generateIV(16);
                    case DES:
                    case TRIPLE_DES:
                        return generateIV(8);
                    default:
                        throw new GenerateException("지원하지 않는 알고리즘 입니다.");
                }
            case CCM:
            case GCM:
                switch (algorithm) {
                    case AES:
                    case ARIA:
                    case LEA:
                    case SEED:
                    case SERPENT:
                    case TRIPLE_DES:
                        return generateIV(12);
                    default:
                        throw new GenerateException("지원하지 않는 알고리즘 입니다.");
                }
            default:
                throw new GenerateException("지원하지 않는 모드 입니다.");
        }
    }
}
