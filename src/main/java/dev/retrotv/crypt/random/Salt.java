package dev.retrotv.crypt.random;

public class Salt {

    public static String generate(SecurityStrength securityStrength, int len) {
        return RandomValue.generate(securityStrength, len);
    }
}
