package dev.retrotv.crypto.cipher.etc;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dev.retrotv.crypto.cipher.block.algorithm.AES;
import dev.retrotv.crypto.cipher.block.mode.CCM;
import dev.retrotv.crypto.cipher.block.mode.GCM;

class TagTest {
    
    @Test
    @DisplayName("CCM Tag 길이 유효성 검증")
    void test_ccmTagLengthValidation() {
        CCM mode = new CCM(new AES());

        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(0));
        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(13));
        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(1));
        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(18));
    }

    @Test
    @DisplayName("GCM Tag 길이 유효성 검증")
    void test_gcmTagLengthValidation() {
        GCM mode = new GCM(new AES());

        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(1));
        assertThrows(IllegalArgumentException.class, () -> mode.updateTagLength(18));
    }
}
