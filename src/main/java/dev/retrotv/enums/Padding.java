package dev.retrotv.enums;

public enum Padding {
      PADDING("PKCS5Padding")
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
