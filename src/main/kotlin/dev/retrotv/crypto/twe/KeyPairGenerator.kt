package dev.retrotv.crypto.twe

import dev.retrotv.crypto.exception.KeyGenerateException
import java.security.KeyPair

/**
 * 키 페어 생성 메소드 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
fun interface KeyPairGenerator {

    /**
     * 비대칭 키 암호화에 사용될 공개 키/개인 키 쌍을 생성하고 반환합니다.
     *
     * @return 생성 된 키 쌍
     */
    @Throws(KeyGenerateException::class)
    fun generateKeyPair(): KeyPair
}
