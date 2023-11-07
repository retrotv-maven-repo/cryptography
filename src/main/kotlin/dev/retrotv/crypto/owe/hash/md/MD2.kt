package dev.retrotv.crypto.owe.hash.md

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.crypto.twe.aes.log
import dev.retrotv.enums.HashAlgorithm
import dev.retrotv.utils.EncodeUtil
import dev.retrotv.utils.MessageDigestEncodeUtil

/**
 * MD2 알고리즘으로 암호화 하기 위한 [MessageDigestEncodeUtil] 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class MD2 : Hash() {
    override fun hash(data: ByteArray): String {
        return EncodeUtil.binaryToHex(MessageDigestEncodeUtil.encode(HashAlgorithm.MD2, data))
    }

    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        log.debug("파일 해싱 이외의 용도로 사용중일 경우, 알고리즘 업그레이드를 권장합니다.");
        return true
    }
}
