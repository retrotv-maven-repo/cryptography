package dev.retrotv.crypt;

/**
 * 암호화 알고리즘을 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public enum Algorithm {
      AES128("AES-128")
    , AES192("AES-192")
    , AES256("AES-256")
    , CRC32("CRC-32")
    , MD2("MD2")
    , MD5("MD5")
    , SHA1("SHA-1")
    , SHA224("SHA-224")
    , SHA256("SHA-256")
    , SHA384("SHA-384")
    , SHA512("SHA-512")
    , SHA512224("SHA-512/224")
    , SHA512256("SHA-512/256")
    ;

    private final String label;

    Algorithm(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
