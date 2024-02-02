package dev.retrotv.crypto.twe.aria

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.lea.Params
import dev.retrotv.crypto.twe.lea.Result
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import org.bouncycastle.crypto.engines.ARIAEngine
import java.security.Key

abstract class ARIA {
    protected val engine = ARIAEngine()
    protected var keyLen = 0
    protected lateinit var algorithm: Algorithm.Cipher

    @Throws(CryptoFailException::class)
    abstract fun encrypt(data: ByteArray, params: Params): Result

    @Throws(CryptoFailException::class)
    abstract fun decrypt(encryptedData: ByteArray, params: Params): Result

    fun generateKey(): Key {
        return ExtendedSecretKeySpec(generate(keyLen / 8), "ARIA")
    }
}