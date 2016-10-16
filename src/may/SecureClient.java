package may;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Hashtable;
import java.util.NoSuchElementException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapContext;
import javax.xml.bind.DatatypeConverter;

/**
 * Client that sends an encrypted symmetrical key to the service and receives a
 * message in return.
 * 
 * @author Daniel May
 * @version 2016-10-16.1
 *
 */
public class SecureClient {
	private PublicKey pk;
	private SecretKey sk;
	private String ldap;

	/**
	 * @param ldap
	 */
	public SecureClient(String ldap) {
		this.ldap = ldap;
		generateSecretKey();
		getPublicKey();
	}

	/**
	 * Generates the secret key, that is used for message encryption.
	 */
	private void generateSecretKey() {
		System.out.println("Generating secret key ...");
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			sk = keygen.generateKey();
			System.out.println(sk.toString());
		} catch (NoSuchAlgorithmException nsae) {
			System.err.println("Couldn't create secret key: " + nsae.getMessage());
			System.exit(1);
		} catch (InvalidParameterException ipe) {
			System.err.println("Invalid keysize: " + ipe.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Reads public key from ldap directory.
	 */
	private void getPublicKey() {
		System.out.println("Connecting to LDAP ...");
		// Set up the environment for creating the initial context
		Hashtable<String, Object> env = new Hashtable<>(3);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://" + ldap);

		try {
			// Create the initial context
			Context ctx = new InitialContext(env);

			// Perform lookup and cast to target type
			LdapContext b = (LdapContext) ctx.lookup("cn=group.service1,dc=nodomain,dc=com");

			System.out.println("Receiving public key ...");
			// get the attribute description
			Attributes answer = b.getAttributes("", new String[] { "description" });

			// the attribute's value
			String response = answer.getAll().next().toString().split(" ")[1];

			// closes the context
			ctx.close();

			System.out.println("Parsing public key ...");
			// get binary array from hex string
			byte[] key = DatatypeConverter.parseHexBinary(response);

			// key specifications
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);

			// key factory for RSA
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			// generate public key from the specification
			pk = keyFactory.generatePublic(pubKeySpec);
		} catch (NamingException | NoSuchElementException ne) {
			System.err.println("Couldn't get the public key: " + ne.getMessage());
			System.exit(1);
		} catch (NoSuchAlgorithmException | IllegalArgumentException | InvalidKeySpecException nsae) {
			System.err.println("Couldn't parse the public key: " + nsae.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Encrypts the secret key with the public key from the service
	 * 
	 * @return byte array of the encrypted secret key
	 */
	byte[] encryptSecretKey() {
		System.out.println("Encrypting secret key ...");
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pk);
			return cipher.doFinal(sk.getEncoded());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException | IllegalStateException e) {
			System.err.println("Couldn't encrypt the secret key: " + e.getMessage());
			System.exit(1);
			return null;
		}
	}

	/**
	 * Decrypts a message using the secret key.
	 * 
	 * @param msg
	 *            message to decrypt
	 * @return decrypted message
	 */
	String decryptMessage(byte[] msg) {
		System.out.println("Decrypting message ...");
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, sk);
			byte[] ready = cipher.doFinal(msg);
			return new String(ready);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException e) {
			System.err.println("Couldn't decrypt message: " + e.getMessage());
			System.exit(1);
			return null;
		}
	}
}