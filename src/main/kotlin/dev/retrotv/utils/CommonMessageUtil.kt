package dev.retrotv.utils

import java.text.MessageFormat
import java.util.*

class CommonMessageUtil private constructor() {

    init {
        throw IllegalStateException("유틸리티 클래스 입니다.")
    }

    companion object {
        private val resourceBundle = ResourceBundle.getBundle("message")
        fun getMessage(key: String): String {
            return resourceBundle.getString(key)
        }

        fun getMessage(key: String, vararg word: Any?): String {
            return MessageFormat.format(resourceBundle.getString(key), *word)
        }
    }
}
