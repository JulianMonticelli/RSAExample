import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

public class MySign {
    private static boolean DEBUG = false;
    private static boolean sign = false;
    private static String fileName;
    private static File file;
    private static ObjectInputStream ois;
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        if(args.length != 2) {
            System.err.println("Insufficient command line arguments.\nRun as: java MySign [s/v] filename.ext");
            System.exit(-1);
        } else {
            if(args[0].equalsIgnoreCase("s") || args[0].equalsIgnoreCase("v")) {
                if(args[0].equalsIgnoreCase("s")) sign = true;
                fileName = args[1];
            } else {
                System.err.println("Insufficient command line arguments.\nRun as: java MySign [s/v] filename.ext");
                System.exit(-1);
            }
        }
        file = new File(fileName); // create new File
        if(file.createNewFile()){ // if the file doesn't exist and we created it
            file.delete();
            System.err.println("The file didn't exist, program exiting.");
            System.exit(404); // <-- :-)
        }
        if(sign)    sign();
        else        verify();
    }
    
    private static void sign() throws IOException, ClassNotFoundException {
        String preSHA = toSHA(file);
        if(DEBUG) System.out.println("SHA pre-Sign: " + preSHA);
        
        // Init privkey
        File privKey = new File("privkey.rsa"); // Init
        if(privKey.createNewFile()) { // Make sure it exists
            privKey.delete();
            System.err.println("There was no private key found in the directory.\nProgram exiting.");
            System.exit(-0714); // Otherwise close
        }
                
        // !-- SIGN SHA-256 HASH OPS --! //
        
        ois = new ObjectInputStream(new FileInputStream(privKey));
        
        // Declare BigIntegers
        BigInteger inSHA = new BigInteger(preSHA, 16); // Create new BigInteger from hex string
        BigInteger n = (BigInteger)ois.readObject(); // Read BigInteger object n
        BigInteger d = (BigInteger)ois.readObject(); // Read BigInteger object d
        BigInteger signedSHA;
        
        // Sign SHA
        signedSHA = inSHA.modPow(d, n); // BigInteger is a really cool class
        if(DEBUG) System.out.println("SHA post-Sign: " + signedSHA);
        // !-- SIGNATURE FILE OPS --! //
        
        // Dealing with the file copy
        
        File sf = new File(fileName + ".signed");
        FileInputStream fis = new FileInputStream(file); // Create new FIS
        
        
        
        // Get message file contents in a String
        fis = new FileInputStream(file); // Create new FIS
        BufferedReader br = new BufferedReader(new InputStreamReader(fis)); // Create BR from FIS
        String fileContents = ""; // String of file contents
        int charVal = 0;
        char currentChar = '~'; // Current line to be pulled from BR
        while((charVal = br.read()) != -1) { // Declare char to be BR's next char and continue if it isn't EOS
            fileContents = fileContents + (char) charVal; // Append current line to file String
        }
        fis.close(); // Close FIS
        
        // Append SHA-256 signed hash to beggining of file, with newline (64 hex digits + 1 newline byte)
        fileContents = signedSHA.toString(16) + "\r\n" + fileContents; // Add signed SHA-256 to file contents at beginning
        sf.delete();
        FileOutputStream fos = new FileOutputStream(sf);
        fos.write(fileContents.getBytes()); //
        fos.flush(); // Flush FOS
        fos.close(); // Close FOS
    }
    private static void verify() throws IOException, ClassNotFoundException {
        String signedHash = "";
        
        // Init privkey
        File pubKey = new File("pubkey.rsa"); // Init
        if(pubKey.createNewFile()) { // Make sure it exists
            pubKey.delete();
            System.err.println("There was no public key found in the directory.\nProgram exiting.");
            System.exit(-0714); // Otherwise close
        }
        
        ois = new ObjectInputStream(new FileInputStream(pubKey));
        
        // Declare BigIntegers
        BigInteger inSHA; // Create new BigInteger from hex string
        BigInteger n = (BigInteger)ois.readObject(); // Read BigInteger object n
        BigInteger e = (BigInteger)ois.readObject(); // Read BigInteger object e
        BigInteger encOGSHA;
        BigInteger ogSHA; // OG SHA
        
        // !-- SIGNATURE FILE OPS --! //
        
        // Dealing with the file copy
        File vf = new File(fileName.substring(0, fileName.length()-7)); // - ".signed"
        FileInputStream fis = new FileInputStream(file); // Create new FIS
                
        // Get message file contents in a String
        fis = new FileInputStream(file); // Create new FIS
        BufferedReader br = new BufferedReader(new InputStreamReader(fis)); // Create BR from FIS
        String fileContents = ""; // String of file contents
        int charVal = 0;
        char currentChar = '~'; // Current line to be pulled from BR
        
        // "Encrypt" SHA
        signedHash = br.readLine(); // Read signed hash in to "encrypt"
        if(DEBUG) System.out.println("Signed Hash: " + signedHash);
        inSHA = new BigInteger(signedHash, 16);
        encOGSHA = inSHA.modPow(e, n); // BigInteger is a really cool class
        
        while((charVal = br.read()) != -1) { // Declare char to be BR's next char and continue if it isn't EOS
            fileContents = fileContents + (char) charVal; // Append current line to file String
        }
        fis.close(); // Close FIS
        vf.delete();
        FileOutputStream fos = new FileOutputStream(vf);
        fos.write(fileContents.getBytes()); //
        fos.flush(); // Flush FOS
        fos.close(); // Close FOS
        String ogSHApreBI = toSHA(vf);
        ogSHA = new BigInteger(ogSHApreBI, 16); // get OG SHA value from verified original file
        if(ogSHA.toString().equals(encOGSHA.toString())) {
            System.out.println("Verified file.");
        } else {
            System.out.println("File failed to verify.");
            System.out.println("encOGSHA = " + encOGSHA + "\nogSHA = " + ogSHApreBI);
        }
    }
    
    /*************************************************************\
     * The following method comes from HashEx.java               *
    \*************************************************************/
    private static String toSHA(File file) { // Thank you Farnan
        String result = "";
        try {
            // read in the file to hash
            Path path = Paths.get(file.toString());
            byte[] data = Files.readAllBytes(path);

            // create class instance to create SHA-256 hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // process the file
            md.update(data);
            // generate a has of the file
            byte[] digest = md.digest();

            // convert the bite string to a printable hex representation
            // note that conversion to biginteger will remove any leading 0s in the bytes of the array!
            result = new BigInteger(1, digest).toString(16);

            // print the hex representation
        }
        catch(Exception e) {
                System.out.println(e.toString());
        }
        return result;
    }
    
}