package dev.retrotv.crypto.twe

import java.security.Key
import java.security.spec.AlgorithmParameterSpec

class Crypto {
    private lateinit var data: ByteArray
    private lateinit var key: Key
    private lateinit var spec: AlgorithmParameterSpec
}