package dev.retrotv.crypt.random;

public enum Algorithm {
      AES128("AES-128")
    , AES192("AES-192")
    , AES256("AES-256")
    ;

    private final String label;

    Algorithm(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
