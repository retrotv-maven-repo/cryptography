package dev.retrotv.crypto.cipher.stream

import dev.retrotv.crypto.cipher.TwoWayEncryption
import dev.retrotv.crypto.cipher.param.Params
import org.bouncycastle.crypto.StreamCipher
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipher : TwoWayEncryption {
    protected lateinit var engine: StreamCipher

    abstract fun encrypt(input: InputStream, output: OutputStream, params: Params)
    abstract fun decrypt(input: InputStream, output: OutputStream, params: Params)
}