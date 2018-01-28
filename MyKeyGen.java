import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
//import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;


public class MyKeyGen {
    private static int KEY_SIZE = 512;
    private static boolean DEBUG = true;
    private static SecureRandom secureRand;
    private static BigInteger p, q, n, phi, e, d, one;
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
        secureRand = new SecureRandom();
        
        // Generate P
        //p = BigInteger.probablePrime(32, secureRand);
        p = BigInteger.probablePrime(KEY_SIZE, secureRand);
        if(DEBUG) System.out.println("p\t=\t" + p);
        
        // Generate Q
        //q = BigInteger.probablePrime(32, secureRand);
        q = BigInteger.probablePrime(KEY_SIZE, secureRand);
        if(DEBUG) System.out.println("q\t=\t" + q);
        
        // Get N
        n = p.multiply(q);
        if(DEBUG) System.out.println("n\t=\t" + n);
        
        // Init BI 1
        one = new BigInteger("1");
        
        // Get Phi(n)
        phi = (p.subtract(one).multiply((q.subtract(one))));
        if(DEBUG) System.out.println("Phi(n)\t=\t" + phi);
        
        // Generate e
        //int ebs = secureRand.nextInt(16) + 16;
        //int ebs = secureRand.nextInt(512) + 256; // e bitsize is between 256 and 768 bits :)
        e = BigInteger.probablePrime(KEY_SIZE/2, secureRand); // Generate 512-bit number that's probably a prime
        while(!phi.gcd(e).equals(one)) { // while e and Phi(n)'s GCD is not 1, get another prime
            //ebs = secureRand.nextInt(16) + 16;
            //ebs = secureRand.nextInt(512) + 256; // randomize bitsize again
            e = BigInteger.probablePrime(KEY_SIZE/2, secureRand);
        } // could loop forever, technically, but probabilistically will not
        if(DEBUG) System.out.println("e\t=\t" + e);
        if(DEBUG) System.out.println("Phi(n) and e have GCD of " + phi.gcd(e));
        
        // Get D
        d = e.modInverse(phi);
        if(DEBUG) System.out.println("d\t=\t" + d);
        
        
        // Output files
        File privKey = new File("privkey.rsa");
        if(privKey.createNewFile()){ // if the file doesn't exist and we created it
	        // Generate new file
        } else {
          privKey.delete(); // delete file
          privKey.createNewFile(); // create file
        }
        File pubKey = new File("pubkey.rsa");
        if(pubKey.createNewFile()){ // if the file doesn't exist and we created it
	        // Generate new file
        } else {
          pubKey.delete(); // delete file
          pubKey.createNewFile(); // create file
        }


        // Write to privKey
        ObjectOutputStream oosPriv = new ObjectOutputStream(new FileOutputStream(privKey));
        oosPriv.writeObject(n); // write N first
        oosPriv.writeObject(d); // write D last
        oosPriv.close(); // close OOS
        
        // Write to pubKey
        ObjectOutputStream oosPub = new ObjectOutputStream(new FileOutputStream(pubKey));
        oosPub.writeObject(n); // write N first
        oosPub.writeObject(e); // write E last
        oosPub.close(); // close OOS
    }
    
    
    
    
}
