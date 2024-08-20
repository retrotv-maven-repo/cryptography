package dev.retrotv.crypto.owe.mac

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.encode
import dev.retrotv.utils.generate
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC (Hash-based message authentication code) 알고리즘 클래스를 구현하기 위한 추상 클래스 입니다.
 */
abstract class HMAC {
    protected lateinit var algorithm: Algorithm.Hmac
    protected val mac: Mac by lazy { Mac.getInstance(this.algorithm.label()) }
    private lateinit var key: Key

    /**
     * 데이터와 키를 이용해 해시된 메시지 인증 코드를 생성하고 반환합니다.
     *
     * @param data
     * @param key
     * @return 해시된 메시지 인증 코드
     */
    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray): String {
        this.key = SecretKeySpec(key, this.algorithm.label())
        mac.init(this.key)

        val hashCode = mac.doFinal(data)
        return ByteUtils.toHexString(hashCode)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray, encodeFormat: EncodeFormat): String {
        this.key = SecretKeySpec(key, this.algorithm.label())
        mac.init(this.key)

        val hashCode = mac.doFinal(data)
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

    fun generateKey(len: Int): ExtendedSecretKeySpec {
        require(len < 1) {
            "인자 len 값이 0보다 같거나 작을 수 없습니다."
        }

        return ExtendedSecretKeySpec(generate(len), "HMAC")
    }

    fun generateKey(encoded: ByteArray): ExtendedSecretKeySpec {
        require(encoded.isEmpty()) {
            "인자 encoded 값은 빈 ByteArray일 수 없습니다."
        }

        return ExtendedSecretKeySpec(encoded, "HMAC")
    }
}