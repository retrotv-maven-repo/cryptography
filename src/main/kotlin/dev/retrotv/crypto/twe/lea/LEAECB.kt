package dev.retrotv.crypto.twe.lea

import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter

/**
 * LEA/ECB 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEAECB(keyLen: Int) : LEA() {

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.LEAECB
    }

    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        val cipher = PaddedBufferedBlockCipher(this.engine)
        cipher.init(true, KeyParameter(key))

        val encryptedData = ByteArray(cipher.getOutputSize(data.size))
        val tam = cipher.processBytes(data, 0, data.size, encryptedData, 0)
        cipher.doFinal(encryptedData, tam)

        return encryptedData
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray): ByteArray {
        val cipher = PaddedBufferedBlockCipher(LEAEngine())
        cipher.init(false, KeyParameter(key))

        val outputData = ByteArray(cipher.getOutputSize(encryptedData.size))
        val tam = cipher.processBytes(encryptedData, 0, encryptedData.size, outputData, 0)
        val finalLen = cipher.doFinal(outputData, tam)
        val originalData = ByteArray(finalLen + tam)

        System.arraycopy(outputData, 0, originalData, 0, tam + finalLen)

        return originalData
    }
}
