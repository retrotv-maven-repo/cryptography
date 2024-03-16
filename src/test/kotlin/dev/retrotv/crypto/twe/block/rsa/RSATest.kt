package dev.retrotv.crypto.twe.block.rsa

internal class RSATest {
//    @Test
//    @DisplayName("RSA-1024 암복호화 테스트")
//    @Throws(
//        GenerateException::class, CryptoFailException::class
//    )
//    fun rsa1024_test() {
//        val keyPairGenerator = RSAKeyPairGenerator(1024)
//        val message = "The lazy dog jumps over the brown fox!"
//        val keyPair = keyPairGenerator.generateKeyPair()
//        val rsa = RSACipher()
//        val encryptedData = rsa.encrypt(message.toByteArray(), keyPair.public)
//        val originalMessage = String(rsa.decrypt(encryptedData, keyPair.private))
//        Assertions.assertEquals(message, originalMessage)
//    }
//
//    @Test
//    @DisplayName("RSA-2048 암복호화 테스트")
//    @Throws(
//        GenerateException::class, CryptoFailException::class
//    )
//    fun rsa2048_test() {
//        val keyPairGenerator = RSAKeyPairGenerator(2048)
//        val message = "The lazy dog jumps over the brown fox!"
//        val keyPair = keyPairGenerator.generateKeyPair()
//        val rsa = RSACipher()
//        val encryptedData = rsa.encrypt(message.toByteArray(), keyPair.public)
//        val originalMessage = String(rsa.decrypt(encryptedData, keyPair.private))
//        Assertions.assertEquals(message, originalMessage)
//    }
//
//    @Test
//    @DisplayName("RSA-1024 전자서명 테스트")
//
//    fun rsa1024_signature_test() {
//        val keyPairGenerator = RSAKeyPairGenerator(1024)
//        val keyPair = keyPairGenerator.generateKeyPair()
//        val signature = RSASignature()
//        val sign = "This is sign"
//        val encryptedSign = signature.sign(sign.toByteArray(), keyPair.private)
//        Assertions.assertTrue(signature.verify(sign.toByteArray(), encryptedSign, keyPair.public))
//    }
//
//    @Test
//    @DisplayName("RSA-2048 전자서명 테스트")
//
//    fun rsa2048_signature_test() {
//        val keyPairGenerator = RSAKeyPairGenerator(2048)
//        val keyPair = keyPairGenerator.generateKeyPair()
//        val signature = RSASignature()
//        val sign = "This is sign"
//        val encryptedSign = signature.sign(sign.toByteArray(), keyPair.private)
//        Assertions.assertTrue(signature.verify(sign.toByteArray(), encryptedSign, keyPair.public))
//    }
//
//    @Test
//    @Throws(IOException::class)
//    fun tcpic() {
//        try {
//            Socket("127.0.0.1", 8888).use { socket -> println("연결성공") }
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//    }
}
