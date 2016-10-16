package may;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Hashtable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.xml.bind.DatatypeConverter;

/**
 * Service class that generates a key pair on startup and stores the public key
 * using LDAP. If the service receives a encrypted symmetrical key, it sends an
 * encrypted message to the client.
 * 
 * @author Daniel May
 * @version 2016-10-16.1
 *
 */
public class SecureService {
	private KeyPair keyPair;
	private String ldap;
	private SecretKey sk;

	/**
	 * Constructor that generates a key pair and stores the public key using
	 * ldap.
	 */
	public SecureService(String ldap) {
		this.ldap = ldap;
		generateKeyPair();
		storePublicKey();
	}

	/**
	 * Generates a key pair.
	 */
	private void generateKeyPair() {
		System.out.println("Generating KeyPair ...");
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			generator.initialize(2048, random);
			keyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException nsae) {
			System.err.println("Algorithm not found: " + nsae.getMessage());
			System.exit(1);
		} catch (InvalidParameterException ipe) {
			System.err.println("Keysize is not supported: " + ipe.getMessage());
			System.exit(1);
		} catch (NoSuchProviderException nspe) {
			System.err.println("Provider not found: " + nspe.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Stores the public key using the ldap directory service.
	 */
	private void storePublicKey() {
		System.out.println("Connecting to LDAP ...");
		// Set up the environment for creating the initial context
		Hashtable<String, Object> env = new Hashtable<>(7);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://" + ldap);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=nodomain,dc=com");
		env.put(Context.SECURITY_CREDENTIALS, "user");

		// Create the initial context
		DirContext ctx;
		try {
			ctx = new InitialDirContext(env);

			ModificationItem[] modifications = new ModificationItem[1];

			// attribute with new value
			Attribute mod = new BasicAttribute("description",
					DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));

			// save as ModificationItem
			modifications[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mod);

			System.out.println("Storing public key ...");
			// actual storing
			ctx.modifyAttributes("cn=group.service1,dc=nodomain,dc=com ", modifications);

			// closes the context
			ctx.close();
		} catch (NamingException ne) {
			System.err.println("Couldn't store the key: " + ne.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Decrypts the secret key using the private key.
	 * 
	 * @param key
	 *            the secret key to decrypt
	 */
	void decryptSecretKey(byte[] key) {
		try {
			System.out.println("Decrypting secret key ...");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte[] ready = cipher.doFinal(key);
			sk = new SecretKeySpec(ready, 0, ready.length, "AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
			System.err.println("Couldn't decrypt the secret key: " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Generates a message with current date and time that is encrypted using
	 * the secret key.
	 */
	byte[] encryptMessage() {
		System.out.println("Enrypting message ...");
		try {
			DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy 'at' HH:mm:ss");
			Date date = new Date();
			String message = "This super secret message was generated on " + dateFormat.format(date);

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sk);
			return cipher.doFinal(message.getBytes());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | IllegalArgumentException | ArrayIndexOutOfBoundsException
				| NullPointerException e) {
			System.err.println("Couldn't encrypt message with secret key: " + e.getMessage());
			e.printStackTrace();
			System.exit(1);
			return null;
		}
	}
}