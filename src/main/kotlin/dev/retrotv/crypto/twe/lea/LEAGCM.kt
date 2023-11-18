package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.crypto.twe.ParameterSpecGenerator
import dev.retrotv.enums.CipherAlgorithm
import dev.retrotv.utils.generate
import kr.re.nsr.crypto.BlockCipher
import kr.re.nsr.crypto.BlockCipherModeAE
import kr.re.nsr.crypto.symm.LEA.GCM
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.spec.GCMParameterSpec

/**
 * LEA/GCM 양방향 암호화 클래스 입니다.
 *
 * @property keyLen 암호화에 사용할 키의 길이 입니다.
 * @author  yjj8353
 * @since   1.0.0
 */
class LEAGCM(keyLen: Int) : LEA(), ParameterSpecGenerator<GCMParameterSpec> {
    private var aad: String? = null

    init {
        require(keyLen == 128 || keyLen == 192 || keyLen == 256) {
            "해당 알고리즘이 지원하지 않는 키 길이 입니다."
        }

        this.keyLen = keyLen
        algorithm = CipherAlgorithm.LEAGCM
    }

    override fun encrypt(data: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return try {
            val cipher: BlockCipherModeAE = GCM()
            val gcmSpec: GCMParameterSpec = spec as GCMParameterSpec

            // GCMParameterSpec의 tLen은 bit 기준이고, taglen이 byte 크기여야 하므로 8로 나눔
            cipher.init(BlockCipher.Mode.ENCRYPT, key.encoded, gcmSpec.iv, gcmSpec.tLen / 8)
            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }

            cipher.doFinal(data)
        } catch (e: Exception) {
            throw CryptoFailException(e.message!!, e)
        }
    }

    override fun decrypt(encryptedData: ByteArray, key: Key, spec: AlgorithmParameterSpec?): ByteArray {
        return try {
            val cipher: BlockCipherModeAE = GCM()
            val gcmSpec: GCMParameterSpec = spec as GCMParameterSpec

            cipher.init(BlockCipher.Mode.DECRYPT, key.encoded, gcmSpec.iv, gcmSpec.tLen / 8)
            if (aad != null) {
                cipher.updateAAD(aad!!.toByteArray())
            }

            val originalData: ByteArray = cipher.doFinal(encryptedData)
                ?: throw AEADBadTagException("동일한 Tag를 사용해 복호화를 시도했는지 확인 하십시오.")

            originalData
        } catch (e: Exception) {
            throw CryptoFailException(e.message!!, e)
        }
    }

    override fun generateSpec(): GCMParameterSpec {
        return GCMParameterSpec(GCM_TAG_LENGTH * 8, generate(GCM_IV_LENGTH))
    }

    /**
     * 추가 인증 데이터를 업데이트 합니다.
     *
     * @param aad 추가 인증 데이터
     */
    fun updateAAD(aad: String?) {
        this.aad = aad
    }

    companion object {
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
