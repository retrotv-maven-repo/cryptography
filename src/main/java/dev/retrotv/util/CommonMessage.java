package dev.retrotv.util;

import java.text.MessageFormat;
import java.util.ResourceBundle;

public class CommonMessage {
    private static final ResourceBundle resourceBundle = ResourceBundle.getBundle("message");

    public String getMessage(String key) {
        return resourceBundle.getString(key);
    }

    public String getMessage(String key, Object... word) {
        return MessageFormat.format(resourceBundle.getString(key), word);
    }
}
