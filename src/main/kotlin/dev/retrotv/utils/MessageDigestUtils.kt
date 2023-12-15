@file:JvmName("MessageDigestEncodeUtils")
package dev.retrotv.utils

import dev.retrotv.enums.HashAlgorithm
import org.apache.logging.log4j.LogManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

import dev.retrotv.enums.HashAlgorithm.CRC32
import java.lang.Long.BYTES

private val log = LogManager.getLogger()

/**
 * 지정된 [HashAlgorithm] 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
 *
 * @param algorithm 암호화 시, 사용할 알고리즘
 * @param data 암호화 할 데이터
 * @return 암호화 된 데이터
 */
fun  encode(algorithm: HashAlgorithm, data: ByteArray): ByteArray {
    return if (CRC32 === algorithm) {
        encodeCRC32(data)
    } else try {
        val algorithmName: String = algorithm.label()
        log.debug("알고리즘: {}", algorithmName)

        val md = MessageDigest.getInstance(algorithm.label())
        md.update(data)
        md.digest()
    } catch (ignored: NoSuchAlgorithmException) {
        ByteArray(0)
    }
}

private fun encodeCRC32(data: ByteArray): ByteArray {
    val crc32 = java.util.zip.CRC32()
    crc32.update(data)

    val buffer = ByteBuffer.allocate(BYTES)
    buffer.putLong(crc32.value)

    return buffer.array()
}
