package dev.retrotv.crypt.twe;

import java.security.KeyPair;

import dev.retrotv.crypt.exception.KeyGenerateException;

public interface KeyPairGenerator {

    /**
     * 비대칭 키 암호화에 사용될 공개 키/개인 키 쌍을 생성하고 반환합니다.
     *
     * @throws KeyGenerateException 키 생성이 실패했을 경우 발생
     * @return 생성 된 키 쌍
     */
    KeyPair generateKeyPair() throws KeyGenerateException;
}
