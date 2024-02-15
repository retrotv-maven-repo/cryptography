package dev.retrotv.crypto.twe.rsa

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.BCTwoWayEncryption
import dev.retrotv.crypto.twe.Params
import dev.retrotv.crypto.twe.Result
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.getMessage
import org.apache.logging.log4j.LogManager
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.encodings.PKCS1Encoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.SecretKeySpec

/**
 * RSA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class RSACipher {
    private val engine = PKCS1Encoding(RSAEngine())
    private val algorithm = Algorithm.Cipher.RSA

    @Throws(CryptoFailException::class)
    fun encrypt(data: ByteArray, params: RSAKeyParameters): Result {
        engine.init(true, params)
        val encryptedData = engine.processBlock(data, 0, data.size)

        return Result(encryptedData)
    }

    @Throws(CryptoFailException::class)
    fun decrypt(encryptedData: ByteArray, params: CipherParameters): Result {
        engine.init(false, params)
        val originalData = engine.processBlock(encryptedData, 0, encryptedData.size)

        return Result(originalData)
    }
}