package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.CRC32
import dev.retrotv.crypto.exception.AlgorithmNotFoundException
import dev.retrotv.crypto.util.MessageDigestUtils.hashing
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.ByteUtils
import org.slf4j.LoggerFactory

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [BinaryHash], [PlaintextHash] 인터페이스를 상속받습니다.
 */
class Hash private constructor() : BinaryHash, PlaintextHash {
    private val log = LoggerFactory.getLogger(this::class.java)
    private lateinit var algorithm: EHash

    companion object {
        private var instance: Hash? = null

        /**
         * 지정된 해시 알고리즘 인스턴스를 반환합니다.
         *
         * @param algorithm 해시 알고리즘
         * @return 해시 인스턴스
         */
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

        /**
         * 지정된 해시 알고리즘 인스턴스를 반환합니다.
         *
         * @param algorithm 해시 알고리즘
         * @return 해시 인스턴스
         * @throws AlgorithmNotFoundException 지원하지 않는 알고리즘일 경우 던짐
         */
        @JvmStatic
        fun getInstance(algorithm: String): Hash {
            try {
                return getInstance(EHash.valueOf(algorithm))
            } catch (e: IllegalArgumentException) {
                throw AlgorithmNotFoundException("지원하지 않는 알고리즘 입니다.", e)
            }
        }
    }

    override fun hashing(data: ByteArray): ByteArray {
        log.debug("선택된 해시 알고리즘: {}", algorithm.label())

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
        log.debug("인코딩 포맷 유형: {}", encoderFormat.name)

        if (digest == null) {
            log.warn("digest가 null 입니다.")
            return false
        }

        val encodedData = ByteUtils.toHexString(hashing(data))
        return encodedData.equals(digest, ignoreCase = true)
    }
}
