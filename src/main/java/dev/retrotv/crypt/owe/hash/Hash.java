package dev.retrotv.crypt.owe.hash;

import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.PasswordWithSalt;
import lombok.NonNull;

import java.nio.charset.Charset;

public abstract class Hash implements Checksum, PasswordWithSalt {

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        return PasswordWithSalt.super.encode(rawPassword);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset) {
        return PasswordWithSalt.super.encode(rawPassword, charset);
    }
}
