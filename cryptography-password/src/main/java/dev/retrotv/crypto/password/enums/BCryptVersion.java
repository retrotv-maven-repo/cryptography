package dev.retrotv.crypto.password.enums;

/**
 * BCrypt 버전을 나타내는 열거형 클래스입니다.
 */
public enum BCryptVersion {
    $2A("$2a"),
    $2Y("$2y"),
    $2B("$2b");

    private final String version;

    BCryptVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }
}