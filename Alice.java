import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.LinkedList;

/**
 * Created by chendi on 26/10/15.
 */

public class Alice {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java Alice BobIP BobPort");
            System.exit(1);
        } else {
            SendEngine engine = null;
            try {
                engine = new SendEngine(args[0], Integer.parseInt(args[1]));
                engine.run();
            } catch (Exception e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        }
    }
}

class SendEngine {
    private Socket connectionSkt;
    private ObjectOutputStream toBob;
    private ObjectInputStream fromBob;

    private final String OUTPUT_FILE = "Message_From_Bob.txt";
    private final String PUB_KEY_FILE = "bob.pub";

    private final int MSG_LEN = 10;

    public SendEngine(String ipAddress, int portNum) throws IOException {
        this.connectionSkt = new Socket(ipAddress, portNum);
        this.toBob = new ObjectOutputStream(this.connectionSkt.getOutputStream());
        this.fromBob = new ObjectInputStream(this.connectionSkt.getInputStream());
    }

    public void run() throws IOException, ClassNotFoundException {
        // Form a Cryptech class for encryption and decryption
        Cryptech ctech = new Cryptech(this.PUB_KEY_FILE);

        // Send session key
        sendSessionKey(ctech);

        // Receive encrypted message
        receiveMessage(ctech);

        closeToBob();
        closeFromBob();
    }

    private void sendSessionKey(Cryptech ctech) throws IOException {
        this.toBob.writeObject(ctech.getEncryptedSessionKey());
    }

    private void receiveMessage(Cryptech ctech) throws IOException, ClassNotFoundException {
        LinkedList<SealedObject> receivedObjects = getEncryptedMsg();
        LinkedList<String> decryptedMsg = decryptMsg(ctech, receivedObjects);
        writeToFile(decryptedMsg, this.OUTPUT_FILE);
    }

    // Get the encrypted objects from Bob
    private LinkedList<SealedObject> getEncryptedMsg() throws IOException, ClassNotFoundException {
        LinkedList<SealedObject> list = new LinkedList<>();
        for (int i = 0; i < MSG_LEN; i++) {
            list.add((SealedObject) this.fromBob.readObject());
        }
        return list;
    }

    // Get decrypted message list
    private LinkedList<String> decryptMsg(Cryptech ctech, LinkedList<SealedObject> encryptList) {
        LinkedList<String> list = new LinkedList<>();
        for (int i = 0; i < encryptList.size(); i++) {
            list.add(ctech.decryptObject(encryptList.get(i)));
        }
        return list;
    }

    // Write message to file
    private void writeToFile(LinkedList<String> list, String outputFile) throws IOException {
        File file = new File(this.OUTPUT_FILE);
        FileWriter writer = new FileWriter(file);
        for (int i = 0; i < list.size(); i++) {
            writer.write(list.get(i));
            writer.write("\n");
        }
        writer.close();
    }

    // Close output stream
    private void closeToBob() throws IOException {
        this.toBob.close();
    }

    // Close input stream
    private void closeFromBob() throws IOException {
        this.fromBob.close();
    }
}

/*
* A class for encryption and decryption using RSA public key
* */
class Cryptech {
    private PublicKey RSAPublicKey;
    private SecretKey sessionKey;
    private SealedObject encryptedSessionKey;

    public Cryptech(String RSAPublicKeyFile) {
        this.RSAPublicKey = getRSAPublicKey(RSAPublicKeyFile);
        this.sessionKey = generateSessionKey();
        this.encryptedSessionKey = formEncryptedSessionKey();
    }

    // Decrypt Object, return plain text string
    public String decryptObject(SealedObject sealedObject) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.sessionKey);
            return (String) sealedObject.getObject(cipher);

        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.out.println("Error: wrong decrypting message");
            System.exit(1);
            return null;
        }
    }

    // Get the session key encrypted by RSA public key
    public SealedObject getEncryptedSessionKey() {
        return this.encryptedSessionKey;
    }

    // Encrypt the session key and encapsulate it as a SealedObject
    private SealedObject formEncryptedSessionKey() {

        SealedObject sessionKeyObj = null;

        try {
            // getInstance(crypto algorithm/feedback mode/padding scheme)
            // Alice will use the same key/transformation
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.RSAPublicKey);
            sessionKeyObj = new SealedObject(this.sessionKey.getEncoded(), cipher);
        } catch (GeneralSecurityException gse) {
            System.out.println("Error: wrong cipher to encrypt message");
            gse.printStackTrace();
            System.exit(1);
        } catch (IOException ioe) {
            System.out.println("Error creating SealedObject");
            ioe.printStackTrace();
            System.exit(1);
        }

        return sessionKeyObj;
    }

    // Read
    private PublicKey getRSAPublicKey(String keyFile) {
        // read private key from file
        File privKeyFile = new File(keyFile);
        if ( privKeyFile.exists() && !privKeyFile.isDirectory() ) {
            return readPublicKey(keyFile);
        } else {
            System.out.println("Alice cannot find Bob's RSA public key.");
            System.exit(1);
            return null;
        }
    }

    // Read public key from a file
    private PublicKey readPublicKey(String keyFile) {
        try {
            ObjectInputStream ois =
                    new ObjectInputStream(new FileInputStream(keyFile));
            PublicKey key = (PublicKey)ois.readObject();
            ois.close();
            System.out.println("Private key read from file " + keyFile);
            return key;
        } catch (IOException oie) {
            System.out.println("Error reading private key from file");
            System.exit(1);
            return null;
        } catch (ClassNotFoundException cnfe) {
            System.out.println("Error: cannot typecast to class PublicKey");
            System.exit(1);
            return null;
        }
    }

    // Generate a 128 bit session key
    private SecretKey generateSessionKey() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.out.println("Error: cannot generate AES session key");
            System.exit(1);
        }
        return null;
    }
}