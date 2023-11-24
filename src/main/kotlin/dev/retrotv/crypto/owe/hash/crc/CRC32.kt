package dev.retrotv.crypto.owe.hash.crc

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.crypto.twe.aes.log
import dev.retrotv.data.utils.binaryToHex
import dev.retrotv.enums.HashAlgorithm
import dev.retrotv.utils.encode

/**
 * CRC-32 알고리즘으로 암호화 하기 위한 [Hash] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class CRC32 : Hash() {
    override fun hash(data: ByteArray): String {

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return binaryToHex(encode(HashAlgorithm.CRC32, data)).substring(8)
    }

    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        log.debug("파일 해싱 이외의 용도로 사용중일 경우, 알고리즘 업그레이드를 권장합니다.")
        return true
    }
}
