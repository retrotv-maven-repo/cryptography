package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import javax.crypto.spec.IvParameterSpec

class LEACFB(keyLen: Int) : LEA(), ParameterSpecGenerator<IvParameterSpec?> {
    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen)
            throw WrongKeyLengthException()
        }
        this.keyLen = keyLen
        algorithm = CipherAlgorithm.LEACFB
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(SecureRandomUtil.generate(16))
    }
}
