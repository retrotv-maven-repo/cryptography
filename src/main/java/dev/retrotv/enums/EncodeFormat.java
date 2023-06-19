package dev.retrotv.enums;

/**
 * 문자열 인코더를 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public enum EncodeFormat {
      HEX("Hex")
    , BASE64("Base64")
    ;

      private final String label;

      EncodeFormat(String label) {
          this.label = label;
      }

      public String label() {
          return label;
      }
}
