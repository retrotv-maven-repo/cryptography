package dev.retrotv.enums;

public enum Padding {
      OAEP_WITH_SHA1_MGF1_PADDING("OAEPWithSHA-1AndMGF1Padding")
    , OAEP_WITH_SHA256_MGF1_PADDING("OAEPWithSHA-256AndMGF1Padding")
    , PKCS1_PADDING("PKCS1Padding")
    , PKCS5_PADDING("PKCS5Padding")
    , NO_PADDING("NoPadding")
    ;

    private final String label;

    Padding(String label) {
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
