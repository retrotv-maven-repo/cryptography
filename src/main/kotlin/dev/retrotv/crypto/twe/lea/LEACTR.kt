package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.Algorithm
import dev.retrotv.utils.generate
import dev.retrotv.utils.getMessage
import org.bouncycastle.crypto.engines.LEAEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import javax.crypto.spec.IvParameterSpec

/**
 * LEA/CTR 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEACTR(keyLen: Int) : LEA(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            getMessage("exception.wrongKeyLength")
        }

        this.keyLen = keyLen
        algorithm = Algorithm.Cipher.LEACTR
    }

    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = SICBlockCipher.newInstance(LEAEngine())
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))

        val outputData = ByteArray(data.size)
        cipher.processBytes(data, 0, data.size, outputData, 0)

        return outputData
    }

    fun decrypt(encryptedData: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = SICBlockCipher.newInstance(LEAEngine())
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))

        val result = ByteArray(encryptedData.size)
        cipher.processBytes(encryptedData, 0, encryptedData.size, result, 0)

        return result
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(generate(16))
    }
}
