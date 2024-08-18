package dev.retrotv.crypto.owe.hash

import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.hashing
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.nio.charset.Charset

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [FileHash], [PasswordEncoderWithSalt] 인터페이스를 상속받습니다.
 */
abstract class Hash : FileHash, PlaintextHash, PasswordEncoderWithSalt {
    protected val log: Logger = LogManager.getLogger(this.javaClass)
    protected lateinit var algorithm: Algorithm.Hash

    override fun hash(data: ByteArray): String {
        return ByteUtils.toHexString(hashing(this.algorithm, data))
    }

    override fun encode(rawPassword: CharSequence): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray())
    }

    override fun encode(rawPassword: CharSequence, charset: Charset): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray(charset))
    }

    override fun matches(data: ByteArray, digest: String?): Boolean {
        return hash(data) == digest
    }
}
