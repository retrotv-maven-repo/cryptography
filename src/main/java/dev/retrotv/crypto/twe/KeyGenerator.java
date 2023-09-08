package dev.retrotv.crypto.twe;

import dev.retrotv.crypto.exception.KeyGenerateException;

import java.security.Key;

public interface KeyGenerator  {

    /**
     * 암복호화 시, 사용될 키를 생성하고 반환합니다.
     *
     * @return 생성 된 키
     */
    Key generateKey();
}
