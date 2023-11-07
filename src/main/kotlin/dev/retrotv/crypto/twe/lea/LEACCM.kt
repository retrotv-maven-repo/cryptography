package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.exception.WrongKeyLengthException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.SecureRandomUtil
import kr.re.nsr.crypto.BlockCipher
import kr.re.nsr.crypto.BlockCipherModeAE
import kr.re.nsr.crypto.symm.LEA.CCM
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.spec.GCMParameterSpec

class LEACCM(keyLen: Int) : LEA(), ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: String? = null

    init {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen)
            throw WrongKeyLengthException()
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.LEACCM
    }

    @Throws(CryptoFailException::class)
    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return try {
            val cipher: BlockCipherModeAE = CCM()
            val gcmSpec: GCMParameterSpec = spec as GCMParameterSpec

            // GCMParameterSpec의 tLen은 bit 기준이고, taglen이 byte 크기여야 하므로 8로 나눔
            cipher.init(BlockCipher.Mode.ENCRYPT, key.encoded, gcmSpec.iv, gcmSpec.tLen / 8)

            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }

            cipher.doFinal(data)
        } catch (e: Exception) {
            throw CryptoFailException(e.message ?: "예외 상황을 설명할 메시지가 없습니다.", e)
        }
    }

    @Throws(CryptoFailException::class)
    override fun decrypt(encryptedData: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return try {
            val cipher: BlockCipherModeAE = CCM()
            val gcmSpec: GCMParameterSpec = spec as GCMParameterSpec

            cipher.init(BlockCipher.Mode.DECRYPT, key.encoded, gcmSpec.iv, gcmSpec.tLen / 8)

            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }

            val originalData: ByteArray = cipher.doFinal(encryptedData)
                ?: throw AEADBadTagException("동일한 Tag를 사용해 복호화를 시도했는지 확인 하십시오.")
            originalData
        } catch (e: Exception) {
            throw CryptoFailException(e.message ?: "예외 상황을 설명할 메시지가 없습니다.", e)
        }
    }

    override fun generateSpec(): GCMParameterSpec {
        return GCMParameterSpec(GCM_TAG_LENGTH * 8, SecureRandomUtil.generate(GCM_IV_LENGTH))
    }

    fun updateAAD(aad: String?) {
        this.aad = aad
    }

    companion object {
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
