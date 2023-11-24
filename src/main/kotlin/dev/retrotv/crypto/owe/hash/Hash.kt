package dev.retrotv.crypto.owe.hash

import java.nio.charset.Charset

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [Checksum], [PasswordEncoderWithSalt] 인터페이스를 상속받습니다.
 */
abstract class Hash : FileChecksum, PasswordEncoderWithSalt {

    override fun encode(rawPassword: CharSequence): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray())
    }

    override fun encode(rawPassword: CharSequence, charset: Charset): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray(charset))
    }
}
