package dev.retrotv.crypt.exception;

public class RandomValueGenerateException extends RuntimeException {
    public RandomValueGenerateException() {
        super();
    }

    public RandomValueGenerateException(String message) {
        super(message);
    }

    public RandomValueGenerateException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
