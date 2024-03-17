package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import java.io.InputStream
import java.io.OutputStream

abstract class StreamCipherAlgorithm {
    lateinit var engine: StreamCipher
    lateinit var algorithm: Algorithm.Cipher
}