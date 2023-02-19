package dev.retrotv.crypt;

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
