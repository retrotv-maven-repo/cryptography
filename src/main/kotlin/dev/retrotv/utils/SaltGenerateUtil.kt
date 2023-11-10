package dev.retrotv.utils

import dev.retrotv.random.Generator
import dev.retrotv.random.PasswordGenerator
import dev.retrotv.random.enums.SecurityStrength

class SaltGenerateUtil private constructor() {

    init {
        throw IllegalStateException("유틸리티 클래스 입니다.")
    }

    companion object {

        /**
         * 소금을 생성하고 반환합니다.
         * 보안 강도와 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
         *
         * @return 생성된 소금
         */
        fun generateSalt(): String? {
            val rv: Generator = PasswordGenerator(SecurityStrength.MIDDLE)
            rv.generate(16)
            return rv.getValue()
        }

        /**
         * len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
         * 보안 강도는 RandomValue에서 지정한 기본 값으로 설정됩니다.
         *
         * @param len 생성할 소금의 길이
         * @return 생성된 소금
         */
        fun generateSalt(len: Int): String? {
            val rv: Generator = PasswordGenerator(SecurityStrength.MIDDLE)
            rv.generate(len)
            return rv.getValue()
        }

        /**
         * securityStrength 수준의 소금을 생성하고 반환합니다.
         * 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
         *
         * @param securityStrength 보안 강도, [SecurityStrength] 참조
         * @return 생성된 소금
         */
        fun generateSalt(securityStrength: SecurityStrength?): String? {
            val rv: Generator = PasswordGenerator(securityStrength!!)
            rv.generate(16)
            return rv.getValue()
        }

        /**
         * securityStrength의 수준과 len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
         *
         * @param len 생성할 소금의 길이
         * @param securityStrength 보안 강도, [SecurityStrength] 참조
         * @return 생성된 소금
         */
        fun generateSalt(len: Int, securityStrength: SecurityStrength?): String? {
            val rv: Generator = PasswordGenerator(securityStrength!!)
            rv.generate(len)
            return rv.getValue()
        }
    }
}
