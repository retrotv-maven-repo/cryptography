package dev.retrotv.crypto.owe.hash

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.nio.charset.Charset

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [FileHash], [PasswordEncoderWithSalt] 인터페이스를 상속받습니다.
 */
abstract class HashAlgorithm : FileHash, PasswordEncoderWithSalt {
    protected val log: Logger = LogManager.getLogger(this.javaClass)

    override fun encode(rawPassword: CharSequence): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray())
    }

    override fun encode(rawPassword: CharSequence, charset: Charset): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray(charset))
    }
}
