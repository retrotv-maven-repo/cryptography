package dev.retrotv.crypt.aes;

import dev.retrotv.crypt.TwoWayEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public abstract class AESCBC implements TwoWayEncryption {

    @Override
    public byte[] encrypt(byte[] data, String key) {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(key.substring(0, 16).getBytes(StandardCharsets.UTF_8));
        byte[] encryptedData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            encryptedData = cipher.doFinal(data);
        } catch (InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException ignored) { }

        return encryptedData;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, String key) {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec iv = new IvParameterSpec(key.substring(0, 16).getBytes(StandardCharsets.UTF_8));
        byte[] decryptrdData = null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            decryptrdData = cipher.doFinal(encryptedData);
        } catch (InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException ignored) { }

        return decryptrdData;
    }

    @Override
    abstract public String generateKey();
}
