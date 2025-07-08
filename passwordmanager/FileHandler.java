package passwordmanager;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileHandler {
    private static final String DATA_FILE = "credentials.dat";
    private static final String SALT_FILE = "salt.dat";

    // Save credentials list to file
    public static void save(List<Credential> credentials) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(DATA_FILE))) {
            oos.writeObject(credentials);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Load credentials list from file
    @SuppressWarnings("unchecked")
    public static List<Credential> load() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            return new ArrayList<>();
        }
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(DATA_FILE))) {
            return (List<Credential>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    // Save salt bytes to file
    public static void saveSalt(byte[] salt) {
        try (FileOutputStream fos = new FileOutputStream(SALT_FILE)) {
            fos.write(salt);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Load salt bytes from file
    public static byte[] loadSalt() {
        File file = new File(SALT_FILE);
        if (!file.exists()) {
            return null;
        }
        try (FileInputStream fis = new FileInputStream(SALT_FILE)) {
            byte[] salt = new byte[16];
            if (fis.read(salt) != 16) {
                throw new IOException("Invalid salt file");
            }
            return salt;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
