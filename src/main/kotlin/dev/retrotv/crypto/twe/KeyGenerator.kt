package dev.retrotv.crypto.twe

import dev.retrotv.crypto.exception.KeyGenerateException
import java.security.Key

/**
 * 키 생성 메소드 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
fun interface KeyGenerator {

    /**
     * 암복호화 시, 사용될 키를 생성하고 반환합니다.
     *
     * @return 생성 된 키
     */
    fun generateKey(): Key
}
