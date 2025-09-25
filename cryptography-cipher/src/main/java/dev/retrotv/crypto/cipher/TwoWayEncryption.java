package dev.retrotv.crypto.cipher;

import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.result.Result;
import lombok.NonNull;

/**
 * 양방향 암호화(암호화 및 복호화)를 구현하기 위한 인터페이스입니다.
 */
public interface TwoWayEncryption {
    Result encrypt(@NonNull byte[] data, @NonNull Param params);
    Result decrypt(@NonNull byte[] encryptedData, @NonNull Param params);
}
