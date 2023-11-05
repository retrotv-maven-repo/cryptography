package dev.retrotv.crypto.owe.hash

import dev.retrotv.data.utils.read
import java.io.File
import java.io.IOException
import java.nio.charset.Charset

abstract class Hash : Checksum, PasswordWithSalt {
    @Throws(IOException::class)
    override fun hash(file: File): String {
        return hash(read(file))
    }

    override fun matches(data: ByteArray, checksum: String?): Boolean {
        return if (checksum == null) {
            false
        } else checksum == hash(data)
    }

    @Throws(IOException::class)
    override fun matches(file: File, checksum: String?): Boolean {
        return if (checksum == null) {
            false
        } else matches(read(file), checksum)
    }

    override fun matches(data1: ByteArray?, data2: ByteArray?): Boolean {
        return if (data1 == null || data2 == null) {
            false
        } else hash(data1) == hash(data2)
    }

    @Throws(IOException::class)
    override fun matches(file1: File?, file2: File?): Boolean {
        if (file1 == null || file2 == null) {
            return false
        }

        val file1Data = read(file1)
        val file2Data = read(file2)
        return matches(file1Data, file2Data)
    }

    override fun encode(rawPassword: CharSequence): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray())
    }

    override fun encode(rawPassword: CharSequence, charset: Charset): String {
        val password = rawPassword.toString()
        return hash(password.toByteArray(charset))
    }

    override fun encode(rawPassword: CharSequence, salt: CharSequence): String {
        return encode(rawPassword.toString() + salt)
    }

    override fun encode(rawPassword: CharSequence, salt: CharSequence, charset: Charset): String {
        return encode(rawPassword.toString() + salt, charset)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else  encodedPassword == encode(rawPassword.toString())
    }

    override fun matches(rawPassword: CharSequence, salt: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else matches(
            rawPassword.toString() + salt,
            encodedPassword
        )
    }
}
