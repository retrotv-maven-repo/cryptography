package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.enums.CipherAlgorithm
import kr.re.nsr.crypto.BlockCipher
import kr.re.nsr.crypto.BlockCipherMode
import kr.re.nsr.crypto.padding.PKCS5Padding
import kr.re.nsr.crypto.symm.LEA.ECB
import java.security.Key

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
            "해당 알고리즘이 지원하지 않는 키 길이 입니다."
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.LEAECB
    }

    fun encrypt(data: ByteArray, key: Key): ByteArray {
        return try {
            val cipher: BlockCipherMode = ECB()
            cipher.init(BlockCipher.Mode.ENCRYPT, key.encoded)
            cipher.setPadding(PKCS5Padding(16))
            cipher.doFinal(data)
        } catch (e: Exception) {
            throw CryptoFailException(e.message ?: "예외 상황을 설명할 메시지가 없습니다.", e)
        }
    }

    fun decrypt(encryptedData: ByteArray, key: Key): ByteArray {
        return try {
            val cipher: BlockCipherMode = ECB()
            cipher.init(BlockCipher.Mode.DECRYPT, key.encoded)
            cipher.setPadding(PKCS5Padding(16))
            cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            throw CryptoFailException(e.message ?: "예외 상황을 설명할 메시지가 없습니다.", e)
        }
    }
}
