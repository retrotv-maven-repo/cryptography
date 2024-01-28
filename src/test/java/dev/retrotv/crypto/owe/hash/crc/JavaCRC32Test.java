package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.Hash;
import dev.retrotv.crypto.owe.mac.HMAC;
import dev.retrotv.crypto.owe.mac.md.HMACMD5;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JavaCRC32Test {

    @Test
    @DisplayName("fileMatch")
    void test_fileMatch() {
        Hash hash = new CRC32();
        HMAC md5 = new HMACMD5();
        // System.out.println(CodecUtils.encode(EncodeFormat.HEX, md5.generateKey().getEncoded()));
    }
}
