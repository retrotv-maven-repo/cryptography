package dev.retrotv.crypt.random;

import dev.retrotv.crypt.exception.RandomValueGenerateException;

import java.security.SecureRandom;
import java.util.Optional;

/**
 * 랜덤한 값을 생성하기 위한 기능성 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class RandomValue {

    private static final char[] CAPITAL_LETTERS = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
    };

    private static final char[] SMALL_LETTERS = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    };

    private static final char[] NUMBERS = {
        '0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9'
    };

    private static final char[] SPECIAL_CHARS = {
        '[', ']', '{', '}', '(', ')', ',', '.', '/', ';', '\'', '$',
        '^', '&', '+', '=', '#', '@', '~', '!', '-', '_', '%'
    };

    private static final int CAPITAL_LETTERS_LENGTH = CAPITAL_LETTERS.length;
    private static final int SMALL_LETTERS_LENGTH = SMALL_LETTERS.length;
    private static final int NUMBERS_LENGTH = NUMBERS.length;
    private static final int SPECIAL_CHARS_LENGTH = SPECIAL_CHARS.length;

    private static final char[] LOW_STRENGTH_CHARS = getLowStrengthChars();
    private static final char[] MIDDLE_STRENGTH_CHARS = getMiddleStrengthChars();
    private static final char[] HIGH_STRENGTH_CHARS = getHighStrengthChars();

    private static char[] getLowStrengthChars() {
        char[] chars = new char[SMALL_LETTERS_LENGTH + NUMBERS_LENGTH];
        System.arraycopy(
                SMALL_LETTERS
                , 0
                , chars
                , 0
                , SMALL_LETTERS_LENGTH
        );
        System.arraycopy(
                NUMBERS
                , 0
                , chars
                , SMALL_LETTERS_LENGTH
                , NUMBERS_LENGTH
        );

        return chars;
    }

    private static char[] getMiddleStrengthChars() {
        char[] chars = new char[CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH];
        System.arraycopy(
                CAPITAL_LETTERS
                , 0
                , chars
                , 0
                , SMALL_LETTERS_LENGTH
        );
        System.arraycopy(
                SMALL_LETTERS
                , 0
                , chars
                , CAPITAL_LETTERS_LENGTH
                , SMALL_LETTERS_LENGTH
        );
        System.arraycopy(
                NUMBERS
                , 0
                , chars
                , (CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH)
                , NUMBERS_LENGTH
        );

        return chars;
    }

    private static char[] getHighStrengthChars() {
        char[] chars = new char[CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH+ SPECIAL_CHARS_LENGTH];
        System.arraycopy(
                CAPITAL_LETTERS
                , 0
                , chars
                , 0
                , CAPITAL_LETTERS_LENGTH
        );
        System.arraycopy(
                SMALL_LETTERS
                , 0
                , chars
                , CAPITAL_LETTERS_LENGTH
                , SMALL_LETTERS_LENGTH
        );
        System.arraycopy(
                NUMBERS
                , 0
                , chars
                , (CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH)
                , NUMBERS_LENGTH
        );
        System.arraycopy(
                SPECIAL_CHARS
                , 0
                , chars
                , (CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH)
                , SPECIAL_CHARS_LENGTH
        );

        return chars;
    }

    /**
     * {@link SecurityStrength}, len 값을 바탕으로 랜덤 값을 생성하고 반환 합니다.
     *
     * @exception RandomValueGenerateException 매개변수 {@link SecurityStrength} 값이 null이거나, 랜덤 값이 정상적으로 생성되지 않은 경우 발생
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @param len 생성할 랜덤 값 길이
     * @return 생성된 랜덤 값
     */
    public static String generate(SecurityStrength securityStrength, int len) {
        Optional.ofNullable(securityStrength)
                .orElseThrow(() -> new RandomValueGenerateException("securityStrength는 null 일 수 없습니다."));
        String randomValue = null;

        int range;
        StringBuilder sb;

        switch (securityStrength) {
            case LOW:
                range = SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    SecureRandom sr = new SecureRandom();
                    int random = sr.nextInt(range);
                    sb.append(LOW_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case MIDDLE:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    SecureRandom sr = new SecureRandom();
                    int random = sr.nextInt(range);
                    sb.append(MIDDLE_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case HIGH:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH + SPECIAL_CHARS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    SecureRandom sr = new SecureRandom();
                    int random = sr.nextInt(range);
                    sb.append(HIGH_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;
        }

        return Optional.ofNullable(randomValue)
                       .orElseThrow(() -> new RandomValueGenerateException("값이 정상적으로 생성되지 않았습니다."));
    }
}
