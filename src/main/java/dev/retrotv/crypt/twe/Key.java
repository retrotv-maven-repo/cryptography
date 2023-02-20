package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public class Key {

    public static String generate(Algorithm algorithm) {
        int len = getKeyLength(algorithm);
        return RandomValue.generate(SecurityStrength.HIGH, len);
    }

    private static int getKeyLength(Algorithm algorithm) {
        int len = 0;
        switch (algorithm) {
            case AES128:
                len = 16;
                break;

            case AES192:
                len = 24;
                break;

            case AES256:
                len = 32;
                break;
        }

        return len;
    }
}
