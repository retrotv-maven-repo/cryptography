package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.exception.CryptFailException;

public interface Checksum {

    String encode(byte[] data);

    default boolean matches(byte[] data, String checksum) {
        if (data == null || checksum == null) {
            throw new CryptFailException("비교할 data 혹은 checksum 값이 null 입니다.");
        }

        return checksum.equals(encode(data));
    }
}
