package dev.retrotv.crypto.util

import dev.retrotv.crypto.enums.EHash
import dev.retrotv.crypto.enums.EHash.*
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.Long.BYTES
import java.nio.ByteBuffer
import java.security.MessageDigest

object MessageDigestUtils {
    val log: Logger = LoggerFactory.getLogger(MessageDigestUtils::class.java)

    /**
     * 지정된 [EHash] 유형으로 데이터를 해시 하고, 해시 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    fun hashing(algorithm: EHash, data: ByteArray): ByteArray {
        return when (algorithm) {
            CRC32 -> digestCRC32(data)

            MD2, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512224, SHA512256 -> {
                val algorithmName: String = algorithm.label()
                log.debug("알고리즘: {}", algorithmName)

                val md = MessageDigest.getInstance(algorithm.label())
                md.update(data)
                md.digest()
            }

            SHA3224 -> {
                val md = SHA3.DigestSHA3(224)
                md.update(data)
                md.digest()
            }

            SHA3256 -> {
                val md = SHA3.DigestSHA3(256)
                md.update(data)
                md.digest()
            }

            SHA3384 -> {
                val md = SHA3.DigestSHA3(384)
                md.update(data)
                md.digest()
            }

            SHA3512 -> {
                val md = SHA3.DigestSHA3(512)
                md.update(data)
                md.digest()
            }
        }
    }

    // CRC-32 알고리즘만 별도로 해시 로직을 사용
    private fun digestCRC32(data: ByteArray): ByteArray {
        val crc32 = java.util.zip.CRC32()
        crc32.update(data)

        val buffer = ByteBuffer.allocate(BYTES)
        buffer.putLong(crc32.value)

        return buffer.array()
    }
}
