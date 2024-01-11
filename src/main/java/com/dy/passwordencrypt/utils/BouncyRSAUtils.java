package com.dy.passwordencrypt.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class BouncyRSAUtils {
    public static final String defaultPublicKey = "public_key";

    public static void main(String[] args) throws Exception {
        buildKeys();
    }

    static {
        // 添加Bouncy Castle提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void buildKeys() throws Exception {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 获取公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 将公钥和私钥转换为Base64字符串
        String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        System.out.println("公钥：" + publicKeyStr);
        System.out.println("私钥：" + privateKeyStr);

        // 明文
        String plainText = "Hello, RSA!";

        // 加密
        String encryptedData = encrypt(plainText, privateKeyStr);
        System.out.println("加密后的数据：" + encryptedData);

        // 解密
        String decryptedText = decrypt(encryptedData, publicKeyStr);
        System.out.println("解密后的数据：" + decryptedText);
    }

    // 还原公钥
    public static RSAPublicKey restorePublicKey(String publicKeyStr) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    // 还原私钥
    public static RSAPrivateKey restorePrivateKey(String privateKeyStr) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }

    // 加密
    public static String encrypt(String plainText, String privateKeyStr) throws Exception {
        RSAPrivateKey privateKey = restorePrivateKey(privateKeyStr);

        // 创建Cipher对象
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, privateKey);

        // 加密
        byte[] encryptedData = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // 解密
    public static String decrypt(String encryptedData, String publicKeyStr) throws Exception {
        RSAPublicKey publicKey = restorePublicKey(publicKeyStr);

        // 创建Cipher对象
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, publicKey);

        // 解密
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

        return new String(decryptedData);
    }


    // 加密
    public static byte[] encrypt(String plainText, RSAPrivateKey privateKey) throws Exception {
        // 创建Cipher对象
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, privateKey);

        // 加密
        byte[] encryptedData = cipher.doFinal(plainText.getBytes());

        return encryptedData;
    }


    // 解密
    public static String decrypt(byte[] encryptedData, RSAPublicKey publicKey) throws Exception {
        // 创建Cipher对象
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, publicKey);

        // 解密
        byte[] decryptedData = cipher.doFinal(encryptedData);

        return new String(decryptedData);
    }
}
