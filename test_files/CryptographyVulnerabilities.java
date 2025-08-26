// File: CryptographyVulnerabilities.java
// Contains cryptographic API misuse and weak security implementations
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.util.Random;

public class CryptographyVulnerabilities {
    
    // Weak encryption algorithm
    public byte[] encryptSensitiveData(String data, String password) throws Exception {
        // VULNERABLE - DES is cryptographically weak
        Cipher cipher = Cipher.getInstance("DES");
        SecretKeySpec key = new SecretKeySpec(password.getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }
    
    // ECB mode vulnerability
    public byte[] encryptUserData(String data, byte[] keyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        // VULNERABLE - ECB mode reveals patterns in encrypted data
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }
    
    // Weak random number generation for security tokens
    public String generateSecurityToken() {
        Random random = new Random(); // VULNERABLE - not cryptographically secure
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }
    
    // Fixed salt in password hashing
    public String hashUserPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String fixedSalt = "myappsalt123"; // VULNERABLE - same salt for all passwords
        md.update(fixedSalt.getBytes());
        md.update(password.getBytes());
        
        byte[] hashBytes = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    // Weak key generation
    public SecretKey generateWeakKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(64); // VULNERABLE - 64-bit key is too weak
        return keyGen.generateKey();
    }
    
    // Insecure SSL/TLS configuration
    public SSLContext createInsecureSSLContext() throws Exception {
        // VULNERABLE - disables certificate validation
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        context.init(null, trustAllCerts, new SecureRandom());
        return context;
    }
    
    // Hardcoded cryptographic key
    public byte[] decryptData(byte[] encryptedData) throws Exception {
        // VULNERABLE - hardcoded key
        String hardcodedKey = "MySecretKey12345";
        SecretKeySpec key = new SecretKeySpec(hardcodedKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }
}