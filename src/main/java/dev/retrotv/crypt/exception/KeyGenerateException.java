package dev.retrotv.crypt.exception;

public class KeyGenerateException extends Exception {
    public KeyGenerateException() {
        super();
    }

    public KeyGenerateException(String message) {
        super(message);
    }

    public KeyGenerateException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
