package dev.retrotv.crypt.exception;

public class CryptFailException extends RuntimeException {
    public CryptFailException() {
        super();
    }

    public CryptFailException(String message) {
        super(message);
    }

    public CryptFailException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
