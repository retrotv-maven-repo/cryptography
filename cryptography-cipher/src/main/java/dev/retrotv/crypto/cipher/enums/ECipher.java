package dev.retrotv.crypto.cipher.enums;

/**
 * 양방향/전자서명 암호화 알고리즘을 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
public enum ECipher {
    AES("AES"),
    ARIA("ARIA"),
    CHACHA20("ChaCha20"),
    SEED("SEED"),
    LEA("LEA"),
    DES("DES"),
    RC4("RC4"),
    SERPENT("Serpent"),
    TRIPLE_DES("DESede"),
    RSA("RSA/ECB"),
    RSAECB("RSA/ECB"),
    SHA1_WITH_RSA("SHA1WithRSA"),
    SHA256_WITH_RSA("SHA256withRSA");

    private final String label;

    ECipher(String label) {
        this.label = label;
    }

    /**
     * 알고리즘의 label(이름)을 반환합니다.
     *
     * @return 알고리즘 명
     */
    public String label() {
        return label;
    }
}