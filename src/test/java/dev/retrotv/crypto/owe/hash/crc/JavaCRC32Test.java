package dev.retrotv.crypto.owe.hash.crc;

import dev.retrotv.crypto.owe.hash.HashAlgorithm;
import dev.retrotv.crypto.owe.mac.HMAC;
import dev.retrotv.crypto.owe.mac.md.HMACMD5;
import dev.retrotv.data.enums.EncodeFormat;
import dev.retrotv.utils.CodecUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class JavaCRC32Test {

    @Test
    @DisplayName("fileMatch")
    void test_fileMatch() {
        HashAlgorithm hash = new CRC32();
        HMAC md5 = new HMACMD5();
        // System.out.println(CodecUtils.encode(EncodeFormat.HEX, md5.generateKey().getEncoded()));
    }
}
