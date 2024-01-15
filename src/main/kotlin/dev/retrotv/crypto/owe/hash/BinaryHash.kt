package dev.retrotv.crypto.owe.hash

interface BinaryHash {

    fun hash(data: ByteArray): String

    fun matches(data: ByteArray, digest: String?): Boolean
}