package dev.retrotv.crypt.random;

import java.util.Optional;

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

    public static String generate(SecurityStrength securityStrength, int length) {
        Optional.ofNullable(securityStrength).orElseThrow(() -> new NullPointerException("securityStrength는 null 일 수 없습니다."));
        String randomValue = null;

        int range;
        StringBuilder sb;

        switch (securityStrength) {
            case LOW:
                range = SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<length; i++) {
                    int random = (int) (Math.random() * range);
                    sb.append(LOW_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case MIDDLE:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<length; i++) {
                    int random = (int) (Math.random() * range);
                    sb.append(MIDDLE_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;

            case HIGH:
                range = CAPITAL_LETTERS_LENGTH + SMALL_LETTERS_LENGTH + NUMBERS_LENGTH + SPECIAL_CHARS_LENGTH;
                sb = new StringBuilder();

                for(int i=0; i<length; i++) {
                    int random = (int) (Math.random() * range);
                    sb.append(HIGH_STRENGTH_CHARS[random]);
                }

                randomValue = sb.toString();
                break;
        }

        return Optional.ofNullable(randomValue).orElseThrow(() -> new RuntimeException("값이 정상적으로 생성되지 않았습니다."));
    }
}