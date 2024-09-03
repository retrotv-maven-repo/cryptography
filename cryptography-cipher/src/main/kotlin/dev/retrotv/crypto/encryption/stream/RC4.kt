package dev.retrotv.crypto.encryption.stream

import dev.retrotv.crypto.encryption.param.Params
import dev.retrotv.crypto.encryption.result.Result
import org.bouncycastle.crypto.engines.RC4Engine
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import org.bouncycastle.crypto.params.KeyParameter
import java.io.InputStream
import java.io.OutputStream

/**
 * RC4 스트림 암호화 클래스 입니다.
 * @deprecated 해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.
 */
@SuppressWarnings("kotlin:S1133")
@Deprecated("해킹에 취약한 양방향 암호화 알고리즘 입니다. 더 높은 보안성을 지닌 알고리즘 사용을 권장합니다.")
class RC4 : StreamCipher() {
    init {
        this.engine = RC4Engine()
    }

    override fun encrypt(data: ByteArray, params: Params): Result {
        this.engine.init(true, KeyParameter(params.key))

        val encryptedData = ByteArray(data.size)
        this.engine.processBytes(data, 0, data.size, encryptedData, 0)

        return Result(encryptedData)
    }

    override fun encrypt(input: InputStream, output: OutputStream, params: Params) {
        this.engine.init(true, KeyParameter(params.key))

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
        this.engine.init(false, KeyParameter(params.key))

        val originalData = ByteArray(encryptedData.size)
        this.engine.processBytes(encryptedData, 0, encryptedData.size, originalData, 0)

        return Result(originalData)
    }

    override fun decrypt(input: InputStream, output: OutputStream, params: Params) {
        this.engine.init(false, KeyParameter(params.key))

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