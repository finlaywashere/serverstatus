package xyz.finlaym.serverstatus.helper;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The Class RSA.
 */
public class ASymmetric {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static final String RSA = "RSA";

	/**
	 * Gen keys.
	 *
	 * @return the key pair
	 * @throws Exception
	 *             the exception
	 */
	public static KeyPair genKeys(String algo, int length) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
		keyPairGenerator.initialize(length);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	/**
	 * Encrypt.
	 *
	 * @param data
	 *            the data
	 * @param key
	 *            the key
	 * @return the string
	 * @throws Exception
	 *             the exception
	 */
	public static String encrypt(String data, PublicKey key, String algo) throws Exception {
		byte[] dataToEncrypt = data.getBytes();
		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedData = cipher.doFinal(dataToEncrypt);
		return BASE64.encode(encryptedData).replaceAll("\n", "&l");
	}

	public static String sign(String data, PrivateKey key, String algo) throws Exception {
		byte[] dataToEncrypt = data.getBytes();
		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedData = cipher.doFinal(dataToEncrypt);
		return BASE64.encode(encryptedData).replaceAll("\n", "&l");
	}

	/**
	 * Decrypt.
	 *
	 * @param encrypted
	 *            the encrypted
	 * @param key
	 *            the key
	 * @return the string
	 * @throws Exception
	 *             the exception
	 */
	public static String decrypt(String encrypted, PrivateKey key, String algo) throws Exception {
		byte[] dataToDecrypt = BASE64.decode(encrypted.replaceAll("&l", "\n"));
		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedData = cipher.doFinal(dataToDecrypt);
		return new String(decryptedData);
	}

	public static String getSigned(String message, PublicKey key, String algo) throws Exception {
		byte[] dataToDecrypt = BASE64.decode(message.replaceAll("&l", "\n"));
		Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedData = cipher.doFinal(dataToDecrypt);
		return new String(decryptedData);
	}

	public static PublicKey getPublicKeyFromByteArray(byte[] keyBytes, String algo) throws Exception {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(algo);
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	public static PrivateKey getPrivateKeyFromByteArray(byte[] key, String algo) throws Exception {
		return KeyFactory.getInstance(algo).generatePrivate(new PKCS8EncodedKeySpec(key));
	}
	public static PublicKey getPublicKeyFromRSAPrivateKey(PrivateKey key) throws Exception{
		
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec priv = kf.getKeySpec(key, RSAPrivateKeySpec.class);
		
		RSAPrivateCrtKey pCK = (RSAPrivateCrtKey) key;
		
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), pCK.getPublicExponent());

		PublicKey publicKey = kf.generatePublic(keySpec);
		
		return publicKey;
		
	}
}
