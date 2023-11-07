package dev.retrotv.crypto.twe

import java.security.Key

fun interface KeyGenerator {

    /**
     * 암복호화 시, 사용될 키를 생성하고 반환합니다.
     *
     * @return 생성 된 키
     */
    fun generateKey(): Key
}
