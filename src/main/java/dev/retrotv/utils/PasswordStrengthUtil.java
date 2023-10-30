package dev.retrotv.utils;

import static dev.retrotv.data.utils.ValidUtils.*;

public class PasswordStrengthUtil {
    private PasswordStrengthUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }
    
    public static boolean checkLength(int minLength, CharSequence password) {
        return password.length() >= minLength;
    }

    public static boolean isInclude(boolean includeEnglish
                                  , boolean includeLowerCaseEnglish
                                  , boolean includeUpperCaseEnglish
                                  , boolean includeNumber
                                  , boolean includeSpecialCharacter
                                  , CharSequence password) {

        if (includeEnglish && !isIncludeEnglish(password.toString())) {
            return false;
        }

        if (includeLowerCaseEnglish && !isIncludeLowerCase(password.toString())) {
            return false;
        }

        if (includeUpperCaseEnglish && !isIncludeUpperCase(password.toString())) {
            return false;
        }

        if (includeNumber && !isIncludeNumber(password.toString())) {
            return false;
        }

        return !includeSpecialCharacter || isIncludeSpecialCharacter(password.toString());
    }
}
