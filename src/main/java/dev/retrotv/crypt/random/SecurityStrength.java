package dev.retrotv.crypt.random;

public enum SecurityStrength {
      LOW("low", "소문자와 숫자만을 사용합니다.")
    , MIDDLE("middle", "대문자, 소문자 그리고 숫자를 사용합니다.")
    , HIGH("high", "대문자, 소문자, 숫자 그리고 특수문자를 사용합니다.")
    ;

    private final String label;
    private final String explain;

    SecurityStrength(String label, String explain) {
        this.label = label;
        this.explain = explain;
    }

    public String label() {
        return label;
    }

    public  String explain() {
        return explain;
    }
}
