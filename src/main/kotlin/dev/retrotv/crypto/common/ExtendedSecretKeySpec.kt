package dev.retrotv.crypto.common

import dev.retrotv.data.utils.toBase64String
import dev.retrotv.data.utils.toHexString
import dev.retrotv.utils.getMessage
import java.security.Key
import javax.crypto.spec.SecretKeySpec

class ExtendedSecretKeySpec : SecretKeySpec {
    constructor(key: ByteArray, algorithm: String) : super(key, algorithm)
    constructor(key: ByteArray, offset: Int, len: Int, algorithm: String) : super(key, offset, len, algorithm)

    companion object {
        fun toExtendedSecretKeySpec(key: Key): ExtendedSecretKeySpec {
            return ExtendedSecretKeySpec(key.encoded, key.algorithm)
        }
    }

    fun getEncodedByHex(): String {
        if (this.encoded == null || this.encoded.isEmpty()) {
            throw NullPointerException(getMessage("exception.nullPointer.encodedKey"))
        }

        return toHexString(this.encoded)
    }

    fun getEncodedByBase64(): String {
        return toBase64String(this.encoded)
    }
}
