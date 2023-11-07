package dev.retrotv.crypto.twe.aes

import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import javax.crypto.spec.IvParameterSpec

class AESCTR(keyLen: Int) : AES(), ParameterSpecGenerator<IvParameterSpec> {

    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw WrongKeyLengthException()
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.AESCTR
    }

    override fun generateSpec(): IvParameterSpec {
        return IvParameterSpec(SecureRandomUtil.generate(16))
    }
}
