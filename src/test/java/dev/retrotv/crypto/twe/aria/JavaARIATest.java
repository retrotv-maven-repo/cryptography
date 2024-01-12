package dev.retrotv.crypto.twe.aria;

import dev.retrotv.data.utils.ByteUtils;
import dev.retrotv.utils.SecureRandomUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

class JavaARIATest {

    @Test
    void test() {
        byte[] keyBytes = SecureRandomUtils.generate(128/8);
        byte[] targetData = "data".getBytes();

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new ARIAEngine());
        cipher.init(true, new KeyParameter(keyBytes));

        byte[] outputData = new byte[cipher.getOutputSize(targetData.length)];

        System.out.println(targetData.length);

        int tam = cipher.processBytes(targetData, 0, targetData.length, outputData, 0);

        try {
            cipher.doFinal(outputData, tam);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(ByteUtils.toHexString(outputData));
    }
}
