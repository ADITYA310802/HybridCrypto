import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class SecureFileStorage {
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int KEY_SIZE = 2048;
    private static final int BLOCK_SIZE = 16;
    
    public static void main(String[] args) throws Exception {
        // Generate a public/private key pair for the recipient
        KeyPair recipientKeyPair = generateKeyPair();
        PublicKey recipientPublicKey = recipientKeyPair.getPublic();
        PrivateKey recipientPrivateKey = recipientKeyPair.getPrivate();
        
        // Generate a symmetric key for encrypting the file data
        SecretKey symmetricKey = generateSymmetricKey();
        
        // Encrypt the file data using the symmetric key
        byte[] encryptedFileData = encryptFileData("D:\\java\\HybridCryptography\\file.txt", symmetricKey);
        
        // Encrypt the symmetric key using the recipient's public key
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, recipientPublicKey);
        
        // Store the encrypted file data and encrypted symmetric key
        storeEncryptedData(encryptedFileData, encryptedSymmetricKey);
        
        // Retrieve the encrypted file data and encrypted symmetric key
        byte[] retrievedEncryptedFileData = retrieveEncryptedFileData();
        byte[] retrievedEncryptedSymmetricKey = retrieveEncryptedSymmetricKey();
        
        // Decrypt the symmetric key using the recipient's private key
        SecretKey decryptedSymmetricKey = decryptSymmetricKey(retrievedEncryptedSymmetricKey, recipientPrivateKey);
        
        // Decrypt the file data using the decrypted symmetric key
        byte[] decryptedFileData = decryptFileData(retrievedEncryptedFileData, decryptedSymmetricKey);
        
        // Write the decrypted file data to disk
        writeToFile("decrypted_file.txt", decryptedFileData);
        
        System.out.println("File encryption and decryption completed successfully.");
    }
    
    private static void writeToFile(String fileName, byte[] decryptedFileData) {
    	 try {
    	        // Write the decrypted data to the file
    	        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
    	        fileOutputStream.write(decryptedFileData);
    	        fileOutputStream.close();

    	        System.out.println("Decrypted data has been written to " + fileName + " successfully!");
    	    } catch (IOException e) {
    	        System.out.println("An error occurred while writing the decrypted data to the file: " + e.getMessage());
    	    }
		
	}

    private static byte[] decryptFileData(byte[] retrievedEncryptedFileData, SecretKey decryptedSymmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, decryptedSymmetricKey);
        return cipher.doFinal(retrievedEncryptedFileData);
    }

    private static SecretKey decryptSymmetricKey(byte[] retrievedEncryptedSymmetricKey, PrivateKey recipientPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(retrievedEncryptedSymmetricKey);
        return new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");
    }
    
    private static byte[] retrieveEncryptedSymmetricKey() throws IOException {
        Path path = Paths.get("symmetric_key_encrypted.txt");
        return Files.readAllBytes(path);
    }

    private static byte[] retrieveEncryptedFileData() throws IOException {
        FileInputStream fileInputStream = new FileInputStream("file.txt");
        byte[] encryptedData = fileInputStream.readAllBytes();
        fileInputStream.close();
        return encryptedData;
    }

	private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
    
    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(BLOCK_SIZE * 8);
        return keyGenerator.generateKey();
    }
    
    private static byte[] encryptFileData(String filename, SecretKey symmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        
        FileInputStream inputStream = new FileInputStream(filename);
        byte[] inputBytes = new byte[(int) new File(filename).length()];
        inputStream.read(inputBytes);
        inputStream.close();
        
        return cipher.doFinal(inputBytes);
    }
    
    private static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }
    
    private static void storeEncryptedData(byte[] encryptedFileData, byte[] encryptedSymmetricKey) throws IOException {
        FileOutputStream outputStream = new FileOutputStream("symmetric_key_encrypted.txt");
        outputStream.write(encryptedFileData);
        outputStream.write(encryptedSymmetricKey);
    }
}