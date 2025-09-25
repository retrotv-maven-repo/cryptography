package dev.retrotv.crypto.cipher.etc;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import dev.retrotv.crypto.cipher.block.algorithm.AES;
import dev.retrotv.crypto.cipher.block.mode.CBC;
import dev.retrotv.crypto.cipher.block.mode.CCM;
import dev.retrotv.crypto.cipher.block.mode.CFB;
import dev.retrotv.crypto.cipher.block.mode.CTR;
import dev.retrotv.crypto.cipher.block.mode.CTS;
import dev.retrotv.crypto.cipher.block.mode.GCM;
import dev.retrotv.crypto.cipher.block.mode.OFB;
import dev.retrotv.crypto.cipher.param.Param;

class CastingTypeTest {

    @Test
    @DisplayName("CBC - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingCBC() {
        CBC mode = new CBC(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("CCM - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingCCM() {
        CCM mode = new CCM(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("CFB - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingCFB() {
        CFB mode = new CFB(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("CTR - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingCTR() {
        CTR mode = new CTR(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("CTS - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingCTS() {
        CTS mode = new CTS(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("GCM - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingGCM() {
        GCM mode = new GCM(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }

    @Test
    @DisplayName("OFB - enrypt(data, params), decrypt(encryptedData, params): params가 ParamWithIV 타입이 아닌 경우")
    void testCastingOFB() {
        OFB mode = new OFB(new AES());
        byte[] data = "Hello, World!".getBytes();
        byte[] key = "012345678901234".getBytes();
        Param params = new Param(key);

        assertThrows(IllegalArgumentException.class, () -> mode.encrypt(data, params));
        assertThrows(IllegalArgumentException.class, () -> mode.decrypt(data, params));
    }
}
