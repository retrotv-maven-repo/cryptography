package dev.retrotv.crypto.twe.algorithm

import dev.retrotv.crypto.twe.CipherAlgorithm
import dev.retrotv.enums.Algorithm
import org.bouncycastle.crypto.engines.DESedeEngine

@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다.")
class TripleDES : CipherAlgorithm() {

    init {
        this.engine = DESedeEngine()
        this.algorithm = Algorithm.Cipher.TRIPLE_DES
    }

//    override fun generateKey(): ByteArray {
//        val keyGenerationParam = KeyGenerationParameters(SecureRandom(), 0)
//        val keyGenerator = DESedeKeyGenerator()
//            keyGenerator.init(keyGenerationParam)
//
//        return keyGenerator.generateKey()
//    }
}