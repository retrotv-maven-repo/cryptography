package dev.retrotv.crypto.password

interface PasswordEncoder {
    fun encode(rawPassword: CharSequence): String
    fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean
}