@file:JvmName("SecureRandomUtils")
package dev.retrotv.utils

import java.security.SecureRandom

/**
 * 길이가 len인 byte[] 형태의 무작위 데이터를 생성합니다.
 *
 * @param len 생성할 byte[]의 길이
 * @return 생성된 무작위 데이터
 */
fun generate(len: Int): ByteArray {
    val sr = SecureRandom()
    val randomData = ByteArray(len)
    sr.nextBytes(randomData)
    return randomData
}
