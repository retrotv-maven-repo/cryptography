package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.crypto.twe.aes.log
import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.utils.binaryEncode
import dev.retrotv.data.utils.binaryToHex
import dev.retrotv.enums.HashAlgorithm
import dev.retrotv.utils.encode

/**
 * MD5 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class MD5 : Hash() {
    override fun hash(data: ByteArray): String {
        return binaryToHex(encode(HashAlgorithm.MD5, data))
    }

    override fun hash(data: ByteArray, encodeFormat: EncodeFormat): String {
        return binaryEncode(encodeFormat, encode(HashAlgorithm.MD5, data))
    }

    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        log.debug("파일 해싱 이외의 용도로 사용중일 경우, 알고리즘 업그레이드를 권장합니다.")
        return true
    }
}
