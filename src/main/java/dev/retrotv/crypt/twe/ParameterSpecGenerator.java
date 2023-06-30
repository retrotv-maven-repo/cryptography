package dev.retrotv.crypt.twe;

import java.security.spec.AlgorithmParameterSpec;

public interface ParameterSpecGenerator<T extends AlgorithmParameterSpec> {
    T generateSpec();
}
