package dev.retrotv.crypto.encryption.stream

import dev.retrotv.crypto.encryption.TwoWayEncryption
import dev.retrotv.crypto.encryption.param.Params
import org.bouncycastle.crypto.StreamCipher
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipher : TwoWayEncryption {
    protected lateinit var engine: StreamCipher

    abstract fun encrypt(input: InputStream, output: OutputStream, params: Params)
    abstract fun decrypt(input: InputStream, output: OutputStream, params: Params)
}