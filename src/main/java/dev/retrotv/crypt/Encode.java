package dev.retrotv.crypt;

/**
 * 문자열 인코더를 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public enum Encode {
      HEX("Hex")
    , BASE64("Base64")
    ;

      private final String label;

      Encode(String label) {
          this.label = label;
      }

      public String label() {
          return label;
      }
}
