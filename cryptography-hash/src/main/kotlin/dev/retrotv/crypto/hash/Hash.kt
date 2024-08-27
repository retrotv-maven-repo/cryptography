package dev.retrotv.crypto.hash

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.CRC32
import dev.retrotv.crypto.util.hashing
import dev.retrotv.data.utils.ByteUtils

/**
 * 해시 알고리즘 클래스 구현을 위한 추상 클래스 입니다.
 * [FileHash], [PlaintextHash] 인터페이스를 상속받습니다.
 */
open class Hash private constructor() : FileHash, PlaintextHash {
    private lateinit var algorithm: EHash

    companion object {
        private var instance: Hash? = null

        fun newInstance(algorithm: EHash): Hash {

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

    override fun hash(data: ByteArray): String {
        return if (algorithm != CRC32) {
            return ByteUtils.toHexString(hashing(algorithm, data))
        } else {

            // CRC32 알고리즘일 경우에만 substring(8)을 사용하여 8자리만 반환함
            ByteUtils.toHexString(hashing(algorithm, data)).substring(8)
        }
    }

    override fun matches(data: ByteArray, digest: String?): Boolean {
        return hash(data) == digest
    }
}
