package dev.retrotv.utils

import dev.retrotv.data.utils.*

class PasswordStrengthUtil private constructor() {

    init {
        throw IllegalStateException("유틸리티 클래스 입니다.")
    }

    companion object {
        fun checkLength(minLength: Int, password: CharSequence): Boolean {
            return password.length >= minLength
        }

        fun isInclude(
            includeEnglish: Boolean,
            includeLowerCaseEnglish: Boolean,
            includeUpperCaseEnglish: Boolean,
            includeNumber: Boolean,
            includeSpecialCharacter: Boolean,
            password: CharSequence
        ): Boolean {
            if (includeEnglish && !isIncludeEnglish(password.toString())) {
                return false
            }

            if (includeLowerCaseEnglish && !isIncludeLowerCase(password.toString())) {
                return false
            }

            if (includeUpperCaseEnglish && !isIncludeUpperCase(password.toString())) {
                return false
            }

            return if (includeNumber && !isIncludeNumber(password.toString())) {
                false
            } else !includeSpecialCharacter || isIncludeSpecialCharacter(password.toString())
        }
    }
}
