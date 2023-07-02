package dev.retrotv.utils;

import java.text.MessageFormat;
import java.util.ResourceBundle;

public class CommonMessageUtil {
    private static final ResourceBundle resourceBundle = ResourceBundle.getBundle("message");

    CommonMessageUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    public static String getMessage(String key) {
        return resourceBundle.getString(key);
    }

    public static String getMessage(String key, Object... word) {
        return MessageFormat.format(resourceBundle.getString(key), word);
    }
}
