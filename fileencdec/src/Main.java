import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage:");
            System.err.println("  java Main encrypt <input-file> <output-file>");
            System.err.println("  java Main decrypt <input-file> <output-file>");
            return;
        }

        String command = args[0].toLowerCase();
        Path inputFile = Path.of(args[1]);
        Path outputFile = Path.of(args[2]);

        char[] password = readPassword("Enter password: ");
        if (password == null || password.length == 0) {
            System.err.println("Password required.");
            return;
        }

        try {
            if ("encrypt".equals(command)) {
                encryptFile(inputFile, outputFile, password);
                System.out.println("Encryption complete: " + outputFile.toAbsolutePath());
            } else if ("decrypt".equals(command)) {
                decryptFile(inputFile, outputFile, password);
                System.out.println("Decryption complete: " + outputFile.toAbsolutePath());
            } else {
                System.err.println("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());

        } finally {
            Arrays.fill(password, '\0'); // wipe password
        }
    }

    // -------- Helper Methods --------

    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        System.out.print(prompt);
        Scanner sc = new Scanner(System.in);
        return sc.nextLine().toCharArray();
    }

 
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int ITERATIONS = 65536;
    private static final int KEY_SIZE = 256;
    private static final String MAGIC = "AESFILE"; // file header
    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecretKeySpec deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void encryptFile(Path input, Path output, char[] password) throws Exception {
        byte[] plaintext = Files.readAllBytes(input);

        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        SecretKeySpec key = deriveKey(password, salt);

        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        try (FileOutputStream fos = new FileOutputStream(output.toFile())) {
            fos.write(MAGIC.getBytes());
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
        }
    }

    private static void decryptFile(Path input, Path output, char[] password) throws Exception {
        byte[] all = Files.readAllBytes(input);
        int pos = 0;

        // header check
        byte[] magic = MAGIC.getBytes();
        if (all.length < magic.length + SALT_LENGTH + IV_LENGTH) {
            throw new IllegalArgumentException("Invalid file format.");
        }
        for (int i = 0; i < magic.length; i++) {
            if (all[i] != magic[i]) throw new IllegalArgumentException("Bad file header.");
        }
        pos += magic.length;

        byte[] salt = Arrays.copyOfRange(all, pos, pos + SALT_LENGTH);
        pos += SALT_LENGTH;
        byte[] iv = Arrays.copyOfRange(all, pos, pos + IV_LENGTH);
        pos += IV_LENGTH;
        byte[] ciphertext = Arrays.copyOfRange(all, pos, all.length);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] plaintext = cipher.doFinal(ciphertext);

        try (FileOutputStream fos = new FileOutputStream(output.toFile())) {
            fos.write(plaintext);
        }
    }
}



//output
/*D:\>cd D:\java\fileencdec\src  
 (go to Main.java path)

D:\java\fileencdec\src>javac Main.java
(run this to compile)
(it will create a class in the same folder)

(create input.txt in the same path the run the below command)
D:\java\fileencdec\src>java Main encrypt input.txt encrypted.bin
Enter password:
Encryption complete: D:\java\fileencdec\src\encrypted.bin

D:\java\fileencdec\src>java Main decrypt  encrypted.bin output.txt
Enter password:
Decryption complete: D:\java\fileencdec\src\output.txt
(this will create output.txt no need to create manually)
*/
