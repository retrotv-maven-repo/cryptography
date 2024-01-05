package dev.retrotv.crypto.owe.mac

import dev.retrotv.crypto.exception.KeyGenerateException
import dev.retrotv.crypto.exception.SaltGenerateException
import dev.retrotv.crypto.owe.hash.PasswordEncoderWithSalt
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm
import dev.retrotv.random.PasswordGenerator
import dev.retrotv.random.RandomStringGenerator
import dev.retrotv.random.enums.SecurityStrength
import dev.retrotv.utils.encode
import dev.retrotv.utils.getMessage
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC (Hash-based message authentication code) 알고리즘 클래스를 구현하기 위한 추상 클래스 입니다.
 */
abstract class HMAC {
    protected var algorithm: Algorithm.Hmac? = null
    private var mac: Mac? = null
    private var key: Key? = null

    /**
     * 데이터와 키를 이용해 해시된 메시지 인증 코드를 생성하고 반환합니다.
     *
     * @param data
     * @param key
     * @return 해시된 메시지 인증 코드
     */
    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray): String {
        this.mac = Mac.getInstance(this.algorithm!!.label())
        this.key = SecretKeySpec(key, this.algorithm!!.label())
        mac!!.init(this.key)

        val hashCode = mac!!.doFinal(data)
        return toHexString(hashCode)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray, encodeFormat: EncodeFormat): String {
        this.mac = Mac.getInstance(this.algorithm!!.label())
        this.key = SecretKeySpec(key, this.algorithm!!.label())
        mac!!.init(this.key)

        val hashCode = mac!!.doFinal(data)
        return encode(encodeFormat, hashCode)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun verify(data: ByteArray, key: ByteArray, mac: String): Boolean {
        return mac == hash(data, key)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun verify(data: ByteArray, key: ByteArray, mac: String, encodeFormat: EncodeFormat): Boolean {
        return mac == hash(data, key, encodeFormat)
    }

    @JvmOverloads
    fun generateKey(len: Int = 16, securityStrength: SecurityStrength = SecurityStrength.MIDDLE): String {
        val rv: RandomStringGenerator = PasswordGenerator(securityStrength)
        rv.generate(len)
        return rv.getString() ?: throw SaltGenerateException(getMessage("exception.saltGenerate"))
    }
}