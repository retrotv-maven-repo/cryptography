package dev.retrotv.crypto.owe.hash

import java.nio.charset.Charset

interface PlaintextHash : BinaryHash {

    fun hash(plaintext: CharSequence): String {
        return hash(plaintext.toString()
                             .toByteArray())
    }

    fun hash(plaintext: CharSequence, charset: Charset): String {
        return hash(plaintext.toString()
                             .toByteArray(charset))
    }
}