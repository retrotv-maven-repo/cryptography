package dev.retrotv.crypt.twe.aria;

import org.egovframe.rte.fdl.cryptography.impl.ARIACipher;
import org.egovframe.rte.fdl.cryptography.impl.aria.ARIAEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

public class ARIATest {

    @Test
    @DisplayName("ARIA128 암복호화 테스트")
    void aria128_test() throws InvalidKeyException {
        ARIAEngine aria = new ARIAEngine(128);
        ARIACipher cipher = new ARIACipher();
        cipher.setPassword("0123456789012345");
    }
}
