package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipherAlgorithm {
    lateinit var engine: StreamCipher
    lateinit var algorithm: Algorithm.Cipher

//    fun encrypt(input: InputStream, output: OutputStream, key: ByteArray) {
//        val data = input.read()
//        data.toByte()
//    }
}