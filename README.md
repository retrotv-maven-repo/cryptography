# Cryptography
[![](https://jitpack.io/v/retrotv-maven-repo/cryptography.svg)](https://jitpack.io/#retrotv-maven-repo/cryptography)

Java 및 Kotlin에서 사용할 수 있는 암호화 라이브러리 입니다.

## 지원 JDK
JDK 1.8 이상

## 지원하는 알고리즘

### KDF(Key Derivation Function) 계열
- Argon2
- BCrypt
- Pbkdf2
- SCrypt

### CRC 계열
- CRC-32

### MD 계열
- MD2
- MD5

### SHA 계열
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-512/224
- SHA-512/256

### AES 계열
- AES-128 (ECB PKCS5 Padding)
- AES-128 (CBC PKCS5 Padding)
- AES-192 (ECB PKCS5 Padding)
- AES-192 (CBC PKCS5 Padding)
- AES-256 (ECB PKCS5 Padding)
- AES-256 (CBC PKCS5 Padding)

## 사용법
```JAVA
// 단방향 암호화 (체크섬)
Checksum checksum = new SHA256();
checksum.encode(new File("./image.jpg"));

// 단방향 암호화 (패스워드)
Password password = new BCrypt();
password.encode("!Q@W#E4r5t6y");
```
