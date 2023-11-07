package dev.retrotv.crypto.twe

import java.security.KeyPair

fun interface KeyPairGenerator {

    /**
     * 비대칭 키 암호화에 사용될 공개 키/개인 키 쌍을 생성하고 반환합니다.
     *
     * @return 생성 된 키 쌍
     */
    fun generateKeyPair(): KeyPair
}
