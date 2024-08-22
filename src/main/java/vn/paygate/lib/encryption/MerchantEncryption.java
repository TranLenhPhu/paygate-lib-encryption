/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package vn.paygate.lib.encryption;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 *
 * @author haibui
 */

public class MerchantEncryption {
    
    private SecretKey getSecretKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        String password = "PASSNLsecretKeyGenerate2024";
        String salt = "8036397974428641579L";

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey originalKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return originalKey;
    }


    
    public String encrypt(String securePass)
            throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        
        // Encrypt the data
        Cipher encryptCipher = Cipher.getInstance("AES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, this.getSecretKey());
        byte[] encryptedBytes = encryptCipher.doFinal(securePass.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String encryptCard(String number, String data)
            throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {

        // Encrypt the data
        Cipher encryptCipher = Cipher.getInstance("AES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, this.getSecretKey());
        byte[] encryptedBytes = encryptCipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    
    public String decryptSecurePass(String encryptedSecurePass)
            throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {

        Cipher decryptCipher = Cipher.getInstance("AES");
        decryptCipher.init(Cipher.DECRYPT_MODE, this.getSecretKey());
        byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedSecurePass));
        String decryptedData = new String(decryptedBytes);
        return decryptedData;
    }

    public static String hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(data.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
        for (byte b : encodedhash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }


}
