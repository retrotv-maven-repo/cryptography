package dev.retrotv.crypt.exception;

public class WrongKeyLengthException extends RuntimeException {
    public WrongKeyLengthException() {
        super("지원하지 않는 Key 길이 입니다.");
    }

    public WrongKeyLengthException(String message) {
        super(message);
    }

    public WrongKeyLengthException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
