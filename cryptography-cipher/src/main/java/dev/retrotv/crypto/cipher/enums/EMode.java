package dev.retrotv.crypto.cipher.enums;

/**
 * 암호화 모드 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
public enum EMode {
    ECB("ECB"),
    CBC("CBC"),
    CFB("CFB"),
    OFB("OFB"),
    CTR("CTR"),
    CTS("CTS"),
    CCM("CCM"),
    GCM("GCM");

    private final String label;

    EMode(String label) {
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
