package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.owe.OWETest;
import dev.retrotv.crypt.owe.crc.CRC32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class MD2Test extends OWETest {

    @Test
    @DisplayName("MD5 password encode 테스트")
    void passwordEncrypt() {
        passwordEncrypt(new MD2());
    }
}
