# Cryptography
[![](https://jitpack.io/v/retrotv-maven-repo/cryptography.svg)](https://jitpack.io/#retrotv-maven-repo/cryptography)

Java 및 Kotlin에서 사용할 수 있는 암호화 라이브러리 입니다.

## 지원 JDK
JDK 1.8 이상

## 지원하는 알고리즘

### KDF(키 유도 함수) 계열
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
- AES-128 (ECB, CBC, CFB, OFB, CRT, GCM)
- AES-192 (ECB, CBC, CFB, OFB, CRT, GCM)
- AES-256 (ECB, CBC, CFB, OFB, CRT, GCM)
#### ECB, CBC 모드는 PKCS#5 Padding을 기본으로 사용

### LEA 계열
- LEA-128 (ECB, CBC, OFB, CRT, GCM)
- LEA-192 (ECB, CBC, OFB, CRT, GCM)
- LEA-256 (ECB, CBC, OFB, CRT, GCM)
#### ECB, CBC 모드는 PKCS#5 Padding을 기본으로 사용
#### CFB 모드는 현재 문제가 있으므로 사용하지 말 것

### RSA 계열
- RSA-1024 (OAEPWITHSHA-256ANDMGF1PADDING, SHA256withRSA)
- RSA-2048 (OAEPWITHSHA-256ANDMGF1PADDING, SHA256withRSA)

## 사용법
```JAVA
// 단방향 암호화 (체크섬)
Checksum checksum = new SHA256();
checksum.hash(new File(filePath));

// 단방향 암호화 (키 유도 함수 패스워드)
Password password = new BCrypt();
password.encode(myPassword);

// 단방향 암호화 (salt가 필요한 일반 패스워드)
PasswordWithSalt password = new SHA256();
password.encode(myPassword, salt);

// 양방향 암호화 (암/복호화)
TwoWayEncryption twe = new AESCBC(128);
byte[] encryptedData = twe.encrypt(data, key, iv);
byte[] originalData = twe.decrypt(encryptedData, key, iv);

// 양방향 암호화 (전자서명)
DigitalSignature ds = new RSA2048();
byte[] encryptedData = ds.sign(data, privateKey);
boolean verifyResult = ds.verify(encryptedData, publicKey);
```
