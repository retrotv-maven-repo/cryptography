package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Encrypt;
import dev.retrotv.crypt.owe.Password;

import java.nio.charset.StandardCharsets;

public class MD4 extends Encrypt implements Checksum, Password {

    @Override
    public String encode(byte[] data) {
        return Encode.binaryToHex(encrypt(Algorithm.MD4, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(StandardCharsets.UTF_8));
    }
}
