package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.KeyGenerateException;

import java.security.Key;

public interface KeyGenerator  {

    /**
     * 암복호화 시, 사용될 키를 생성하고 반환합니다.
     *
     * @throws KeyGenerateException 키 생성이 실패했을 경우 발생
     * @return 생성 된 키
     */
    Key generateKey() throws KeyGenerateException;
}
