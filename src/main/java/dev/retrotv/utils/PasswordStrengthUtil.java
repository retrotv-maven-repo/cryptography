package dev.retrotv.utils;

import dev.retrotv.data.utils.StringUtils;

public class PasswordStrengthUtil {
    private PasswordStrengthUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }
    
    public static boolean checkLength(int minLength, CharSequence password) {
        return password.length() < minLength;
    }

    public static boolean isInclude(boolean includeEnglish
                                  , boolean includeLowerCaseEnglish
                                  , boolean includeUpperCaseEnglish
                                  , boolean includeNumber
                                  , boolean includeSpecialCharacter
                                  , CharSequence password) {

        if (includeEnglish && !StringUtils.isIncludeEnglish(password.toString())) {
            return false;
        }

        if (includeLowerCaseEnglish && !StringUtils.isIncludeLowerCase(password.toString())) {
            return false;
        }

        if (includeUpperCaseEnglish && !StringUtils.isIncludeUpperCase(password.toString())) {
            return false;
        }

        if (includeNumber && !StringUtils.isIncludeNumber(password.toString())) {
            return false;
        }

        if (includeSpecialCharacter && !StringUtils.isIncludeSpecialCharacter(password.toString())) {
            return false;
        }

        return true;
    }
}
