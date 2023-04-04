package dev.retrotv.crypt.random;

import dev.retrotv.crypt.exception.RandomValueGenerateException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.SecureRandom;

/**
 * 무작위 값을 생성하기 위한 기능성 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class RandomValue {
    private static final Logger logger = LogManager.getLogger();

    private static final int DEFAULT_LENGTH = 16;
    private static final SecurityStrength DEFAULT_SECURITY_STRENGTH = SecurityStrength.MIDDLE;

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
     * 무작위 값을 생성하고 반환 합니다.
     * SecurityStrength는 기본 값(DEFAULT_SECURITY_STRENGTH)으로 설정됩니다.
     * len은 기본 값(DEFAULT_LENGTH)으로 설정됩니다.
     *
     * @exception RandomValueGenerateException 매개변수 len이 0보다 작거나, 무작위 값이 정상적으로 생성되지 않은 경우 발생
     * @return 생성된 무작위 값
     */
    public static String generate() {
        return generate(DEFAULT_SECURITY_STRENGTH, DEFAULT_LENGTH);
    }

    /**
     * len 값을 바탕으로 무작위 값을 생성하고 반환 합니다.
     * SecurityStrength는 기본 값(DEFAULT_SECURITY_STRENGTH)으로 설정됩니다.
     *
     * @exception RandomValueGenerateException 매개변수 len이 0보다 작거나, 무작위 값이 정상적으로 생성되지 않은 경우 발생
     * @param len 생성할 무작위 값 길이
     * @return 생성된 무작위 값
     */
    public static String generate(int len) {
        return generate(DEFAULT_SECURITY_STRENGTH, len);
    }

    /**
     * {@link SecurityStrength} 값을 바탕으로 무작위 값을 생성하고 반환 합니다.
     * SecurityStrength가 null인 경우 기본 값(DEFAULT_SECURITY_STRENGTH)으로 설정됩니다.
     * len은 기본 값(DEFAULT_LENGTH)으로 설정됩니다.
     *
     * @exception RandomValueGenerateException 매개변수 len이 0보다 작거나, 무작위 값이 정상적으로 생성되지 않은 경우 발생
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @return 생성된 무작위 값
     */
    public static String generate(SecurityStrength securityStrength) {
        return generate(securityStrength, DEFAULT_LENGTH);
    }

    /**
     * {@link SecurityStrength}, len 값을 바탕으로 무작위 값을 생성하고 반환 합니다.
     * SecurityStrength가 null인 경우 기본 값(DEFAULT_SECURITY_STRENGTH)으로 설정됩니다.
     *
     * @exception RandomValueGenerateException 매개변수 len이 0보다 작거나, 무작위 값이 정상적으로 생성되지 않은 경우 발생
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @param len 생성할 무작위 값 길이
     * @return 생성된 무작위 값
     */
    public static String generate(SecurityStrength securityStrength, int len) {
        if (len < 0) {
            logger.error("생성할 무작위 값 길이 len은 0보다 작을 수 없습니다.");
            throw new RandomValueGenerateException("생성할 무작위 값 길이 len은 0보다 작을 수 없습니다.");
        }

        if (securityStrength == null) {
            logger.error("securityStrength가 null 입니다.");
            throw new RandomValueGenerateException("securityStrength가 null 입니다.");
        }

        int range;
        StringBuilder sb;
        String randomValue = null;
        SecureRandom sr = new SecureRandom();

        switch (securityStrength) {
            case LOW:
                range = SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    int random = sr.nextInt(range);
                    sb.append(LOW_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case MIDDLE:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    int random = sr.nextInt(range);
                    sb.append(MIDDLE_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case HIGH:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH + SPECIAL_CHARS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<len; i++) {
                    int random = sr.nextInt(range);
                    sb.append(HIGH_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;
        }

        return randomValue;
    }
}
