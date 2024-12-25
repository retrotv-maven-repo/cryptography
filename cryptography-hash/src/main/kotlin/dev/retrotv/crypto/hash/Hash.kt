package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.CRC32
import dev.retrotv.crypto.util.MessageDigestUtils.hashing
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.ByteUtils

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [BinaryHash], [PlaintextHash] 인터페이스를 상속받습니다.
 */
class Hash private constructor() : BinaryHash, PlaintextHash {
    private lateinit var algorithm: EHash

    companion object {
        private var instance: Hash? = null

        @JvmStatic
        fun getInstance(algorithm: EHash): Hash {

            // 알고리즘이 같으면 동일한 인스턴스를 반환하고, 아니라면 새로운 인스턴스를 생성해 반환함
            if (instance != null && instance?.algorithm != algorithm) {
                instance = null
            }

            // Thread-safe한 싱글톤 패턴 구현
            return instance ?: synchronized(this) {
                instance ?: Hash().also {
                    it.algorithm = algorithm
                    instance = it
                }
            }
        }
    }

    override fun hash(data: ByteArray): ByteArray {
        return if (algorithm != CRC32) {
            hashing(algorithm, data)
        } else {

            // CRC32 해시 알고리즘은 마지막 4바이트 해시 값을 반환함
            val hashedData = hashing(algorithm, data)
            hashedData.copyOfRange(4, 8)
        }
    }

    override fun matches(data: ByteArray, digest: String?): Boolean {
        return matches(data, digest, EncodeFormat.HEX)
    }

    override fun matches(data: ByteArray, digest: String?, encoderFormat: EncodeFormat): Boolean {
        val encodedData = ByteUtils.toHexString(hash(data))
        return encodedData.equals(digest, ignoreCase = true)
    }
}
