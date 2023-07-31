import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FolderLocker {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java FolderLocker <folder_path>");
            return;
        }

        String folderPath = args[0];
        boolean locked = true; // Change this to unlock the folder

        try {
            if (locked) {
                System.out.print("Enter password to lock the folder: ");
                Scanner scanner = new Scanner(System.in);
                String password = scanner.nextLine();
                lockFolder(folderPath, password);
                System.out.println("Folder locked successfully!");
                scanner.close();
            } else {
                System.out.print("Enter password to unlock the folder: ");
                Scanner scanner = new Scanner(System.in);
                String password = scanner.nextLine();
                unlockFolder(folderPath, password);
                System.out.println("Folder unlocked successfully!");
                scanner.close();
            }
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error occurred: " + e.getMessage());
        }
    }

    private static void lockFolder(String folderPath, String password) throws IOException, GeneralSecurityException {
        File folder = new File(folderPath);
        if (folder.exists()) {
            // Encrypt the folder contents
            File[] files = folder.listFiles();
            if (files != null) {
                for (File file : files) {
                    encryptFile(file, password);
                }
            }
        } else {
            throw new IOException("Folder does not exist.");
        }
    }

    private static void unlockFolder(String folderPath, String password) throws IOException, GeneralSecurityException {
        File folder = new File(folderPath);
        if (folder.exists()) {
            // Decrypt the folder contents
            File[] files = folder.listFiles();
            if (files != null) {
                for (File file : files) {
                    decryptFile(file, password);
                }
            }
        } else {
            throw new IOException("Locked folder does not exist.");
        }
    }

    private static void encryptFile(File file, String password) throws IOException, GeneralSecurityException {
        try (FileInputStream in = new FileInputStream(file);
             FileOutputStream out = new FileOutputStream(file.getAbsolutePath() + ".enc")) {

            // Generate a 16-byte key and IV from the password
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = Arrays.copyOf(sha.digest(password.getBytes()), 16);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            byte[] iv = Arrays.copyOf(sha.digest(password.getBytes()), 16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Encrypt the file using AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] inputBuffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(inputBuffer)) != -1) {
                byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    out.write(outputBuffer);
                }
            }

            byte[] outputBuffer = cipher.doFinal();
            if (outputBuffer != null) {
                out.write(outputBuffer);
            }
        }
        // Delete the original unencrypted file
        file.delete();
    }

    private static void decryptFile(File file, String password) throws IOException, GeneralSecurityException {
        try (FileInputStream in = new FileInputStream(file);
             FileOutputStream out = new FileOutputStream(file.getAbsolutePath().replace(".enc", ""))) {

            // Generate a 16-byte key and IV from the password
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = Arrays.copyOf(sha.digest(password.getBytes()), 16);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            byte[] iv = Arrays.copyOf(sha.digest(password.getBytes()), 16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Decrypt the file using AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] inputBuffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(inputBuffer)) != -1) {
                byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    out.write(outputBuffer);
                }
            }

            byte[] outputBuffer = cipher.doFinal();
            if (outputBuffer != null) {
                out.write(outputBuffer);
            }
        }
        // Delete the encrypted file
        file.delete();
    }
}
