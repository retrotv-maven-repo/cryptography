package dev.retrotv.crypto.cipher.block.vector;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.algorithm.ARIA;
import dev.retrotv.crypto.cipher.block.algorithm.LEA;
import dev.retrotv.crypto.cipher.block.mode.ECB;
import dev.retrotv.crypto.cipher.param.Param;
import dev.retrotv.data.utils.ByteUtils;
import dev.retrotv.data.utils.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

class ECBTest {
    private byte[] hexToBytes(String hex) throws Exception { return StringUtils.hexToByteArray(hex); }
    private String bytesToHex(byte[] bytes) { return ByteUtils.toHexString(bytes).toUpperCase(); }

    private static final String[] ALGORITHM = {"ARIA", "LEA"};
    private static final int[] KEY_LENGTH = {128, 192, 256};

    @TestFactory
    Stream<DynamicTest> test_ecbKat() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String algorithm : ALGORITHM) {
            BlockCipher blockCipher;
            if (algorithm.equals("ARIA")) {
                blockCipher = new ARIA();
            } else if (algorithm.equals("LEA")) {
                blockCipher = new LEA();
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
            for (int keyLength : KEY_LENGTH) {
                File file = new File("src/vector/" + algorithm + "/" + algorithm + "-" + keyLength + "_(ECB)_KAT.txt");
                List<String> lines;
                try { lines = java.nio.file.Files.readAllLines(file.toPath()); } catch (Exception e) { continue; }
                String key = "", pt = "", ct = "";
                int caseNum = 1;
                for (String line : lines) {
                    line = line.trim();
                    if (line.startsWith("KEY =")) key = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("PT =")) pt = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("CT =")) {
                        ct = line.substring(line.indexOf('=')+1).trim();
                        String testName = algorithm + "-" + keyLength + "-ECB KAT #" + caseNum;
                        String finalKey = key;
                        String finalPt = pt;
                        String finalCt = ct;
                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            ECB ecb = new ECB(blockCipher);
                            Param params = new Param(hexToBytes(finalKey));
                            byte[] result = ecb.encrypt(hexToBytes(finalPt), params).getData();
                            String resultHex = bytesToHex(result);
                            int ctLength = finalCt.length();
                            Assertions.assertEquals(finalCt.toUpperCase(), resultHex.substring(0, ctLength), "Failed at " + testName);
                        }));
                        caseNum++;
                    }
                }
            }
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> test_ecbMmt() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String algorithm : ALGORITHM) {
            BlockCipher blockCipher;
            if (algorithm.equals("ARIA")) {
                blockCipher = new ARIA();
            } else if (algorithm.equals("LEA")) {
                blockCipher = new LEA();
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
            for (int keyLength : KEY_LENGTH) {
                File file = new File("src/vector/" + algorithm + "/" + algorithm + "-" + keyLength + "_(ECB)_MMT.txt");
                List<String> lines;
                try { lines = java.nio.file.Files.readAllLines(file.toPath()); } catch (Exception e) { continue; }
                String key = "", pt = "", ct = "";
                int caseNum = 1;
                for (String line : lines) {
                    line = line.trim();
                    if (line.startsWith("KEY =")) key = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("PT =")) pt = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("CT =")) {
                        ct = line.substring(line.indexOf('=')+1).trim();
                        String testName = algorithm + "-" + keyLength + "-ECB MMT #" + caseNum;
                        String finalKey = key;
                        String finalPt = pt;
                        String finalCt = ct;
                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            ECB ecb = new ECB(blockCipher);
                            Param params = new Param(hexToBytes(finalKey));
                            byte[] result = ecb.encrypt(hexToBytes(finalPt), params).getData();
                            String resultHex = bytesToHex(result);
                            int ctLength = finalCt.length();
                            Assertions.assertEquals(finalCt.toUpperCase(), resultHex.substring(0, ctLength), "Failed at " + testName);
                        }));
                        caseNum++;
                    }
                }
            }
        }
        return tests.stream();
    }
}

