package dev.retrotv.crypto.owe.mac

import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.binaryEncode
import dev.retrotv.data.utils.binaryToHex
import dev.retrotv.enums.Algorithm
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class HMAC {
    protected var algorithm: Algorithm.Hmac? = null
    private var mac: Mac? = null
    private var key: Key? = null

    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray): String {
        this.mac = Mac.getInstance(this.algorithm!!.label())
        this.key = SecretKeySpec(key, this.algorithm!!.label())
        mac!!.init(this.key)

        val hashCode = mac!!.doFinal(data)
        return binaryToHex(hashCode)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun hash(data: ByteArray, key: ByteArray, encodeFormat: EncodeFormat): String {
        this.mac = Mac.getInstance(this.algorithm!!.label())
        this.key = SecretKeySpec(key, this.algorithm!!.label())
        mac!!.init(this.key)

        val hashCode = mac!!.doFinal(data)
        return binaryEncode(encodeFormat, hashCode)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun verify(data: ByteArray, key: ByteArray, mac: String): Boolean {
        return mac == hash(data, key)
    }

    @Throws(NoSuchAlgorithmException::class)
    fun verify(data: ByteArray, key: ByteArray, mac: String, encodeFormat: EncodeFormat): Boolean {
        return mac == hash(data, key, encodeFormat)
    }
}