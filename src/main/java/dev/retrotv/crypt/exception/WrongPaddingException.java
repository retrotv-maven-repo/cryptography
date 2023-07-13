package dev.retrotv.crypt.exception;

public class WrongPaddingException extends RuntimeException {
    public WrongPaddingException() {
        super("해당 알고리즘에서 지원하지 않는 패딩 기법 입니다.");
    }

    public WrongPaddingException(String message) {
        super(message);
    }

    public WrongPaddingException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
