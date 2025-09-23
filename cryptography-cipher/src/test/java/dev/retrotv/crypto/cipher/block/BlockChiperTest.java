package dev.retrotv.crypto.cipher.block;

import dev.retrotv.crypto.cipher.block.mode.*;
import dev.retrotv.crypto.cipher.generator.IVGenerator;
import dev.retrotv.crypto.cipher.generator.KeyGenerator;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S2187")
public class BlockChiperTest {
    private final String plainText = "The quick brown fox jumps over the lazy dog";

    public void test_ecb(BlockCipher blockCipher, int keyLength) {
        ECB mode = new ECB(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        Param params = new Param(key);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_cbc(BlockCipher blockCipher, int keyLength, int ivLength) {
        CBC mode = new CBC(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_ofb(BlockCipher blockCipher, int keyLength, int ivLength) {
        OFB mode = new OFB(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_cfb(BlockCipher blockCipher, int keyLength, int ivLength) {
        CFB mode = new CFB(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_ctr(BlockCipher blockCipher, int keyLength, int ivLength) {
        CTR mode = new CTR(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_ctsecb(BlockCipher blockCipher, int keyLength) {
        CTS mode = new CTS(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        Param params = new Param(key);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_ctscbc(BlockCipher blockCipher, int keyLength, int ivLength) {
        CTS mode = new CTS(blockCipher);
        mode.useCBCMode();
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(decrypted.getData()));
    }

    public void test_ccm(BlockCipher blockCipher, int keyLength, int ivLength) {
        CCM mode = new CCM(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(((AEADResult)decrypted).getData()));
    }

    public void test_gcm(BlockCipher blockCipher, int keyLength, int ivLength) {
        GCM mode = new GCM(blockCipher);
        byte[] key = KeyGenerator.generateKey(keyLength);
        byte[] iv = IVGenerator.generateIV(ivLength);
        ParamWithIV params = new ParamWithIV(key, iv);

        Result encrypted = mode.encrypt(plainText.getBytes(), params);
        Result decrypted = mode.decrypt(encrypted.getData(), params);

        assertEquals(plainText, new String(((AEADResult)decrypted).getData()));
    }
}

