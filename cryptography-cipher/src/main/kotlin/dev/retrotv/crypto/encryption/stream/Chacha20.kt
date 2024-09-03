package dev.retrotv.crypto.encryption.stream

import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.param.ParamsWithIV
import dev.retrotv.crypto.encryption.result.Result
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.InputStream
import java.io.OutputStream

/**
 * ChaCha20 스트림 암호화 클래스 입니다.
 */
class Chacha20 : StreamCipher() {
    private val requiredMessage = "ChaCha20 모드는 ParamsWithIV 객체를 요구합니다."
    init {
        this.engine = ChaChaEngine(20)
    }

    override fun encrypt(data: ByteArray, params: Params): Result {
        require(params is ParamsWithIV) { requiredMessage }

        this.engine.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    override fun encrypt(input: InputStream, output: OutputStream, params: Params) {
        require(params is ParamsWithIV) { requiredMessage }

        this.engine.init(true, ParametersWithIV(KeyParameter(params.key), params.iv))

        val cos = CipherOutputStream(output, this.engine)
        val buffer = ByteArray(1024)
        var i: Int = input.read(buffer)
        while (i != -1) {
            cos.write(buffer, 0, i)
            i = input.read(buffer)
        }

        cos.flush()
        cos.close()
    }

    override fun decrypt(encryptedData: ByteArray, params: Params): Result {
        require(params is ParamsWithIV) { requiredMessage }

        this.engine.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }

    override fun decrypt(input: InputStream, output: OutputStream, params: Params) {
        require(params is ParamsWithIV) { requiredMessage }

        this.engine.init(false, ParametersWithIV(KeyParameter(params.key), params.iv))

        val cis = CipherInputStream(input, this.engine)
        val buffer = ByteArray(1024)
        var i: Int = cis.read(buffer)
        while (i != -1) {
            output.write(buffer, 0, i)
            i = cis.read(buffer)
        }

        cis.close()
    }
}