package dev.retrotv.crypto.cipher;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import lombok.NonNull;

/**
 * 양방향 암호화(암호화 및 복호화)를 구현하기 위한 인터페이스입니다.
 */
public interface TwoWayEncryption {

    /**
     * 암호화 메서드
     *
     * @param data 암호화할 데이터
     * @param params 암호화에 필요한 파라미터
     * @return 암호화 결과를 담은 Result 객체
     */
    Result encrypt(@NonNull byte[] data, @NonNull Param params);

    /**
     * 복호화 메서드
     *
     * @param encryptedData 암호화된 데이터
     * @param params 복호화에 필요한 파라미터
     * @return 복호화 결과를 담은 Result 객체
     */
    Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params);
}
