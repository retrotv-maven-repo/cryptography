package dev.retrotv.crypto.twe.des

import dev.retrotv.crypto.exception.KeyGenerateException
import java.security.Key
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator

import dev.retrotv.utils.getMessage

abstract class TripleDES : DES() {

    @Throws(KeyGenerateException::class)
    override fun generateKey(): Key {
        return try {
            val keyGenerator = KeyGenerator.getInstance("DESede")
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw KeyGenerateException(getMessage("exception.noSuchAlgorithm"), e)
        }
    }
}