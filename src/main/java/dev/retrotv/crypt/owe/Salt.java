package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public class Salt {

    public static String generate(SecurityStrength securityStrength, int len) {
        return RandomValue.generate(securityStrength, len);
    }
}
