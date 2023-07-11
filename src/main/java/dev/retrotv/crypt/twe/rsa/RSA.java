package dev.retrotv.crypt.twe.rsa;

import dev.retrotv.crypt.exception.WrongKeyLengthException;

import static dev.retrotv.enums.Algorithm.RSA;

public class RSA extends RSACipher {

    public RSA(int keyLen) {
        if (keyLen != 1024 && keyLen != 2048) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = RSA;
    }
}
