package xyz.finlaym.serverstatus.common;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import org.bouncycastle.util.encoders.Base64;

import xyz.finlaym.serverstatus.helper.ASymmetric;

public class KeyManager {
	private PublicKey caKey;
	private KeyPair localKey;
	private Signature signature;
	public KeyManager(PublicKey caKey, KeyPair localKey, Signature signature) {
		this.caKey = caKey;
		this.localKey = localKey;
		this.signature = signature;
	}
	public KeyManager(File caPubF, File privF, File pubF, File sigF) throws Exception{
		Scanner in = new Scanner(caPubF);
		String caPubA = in.nextLine();
		this.caKey = ASymmetric.getPublicKeyFromByteArray(Base64.decode(in.nextLine().replaceAll("&l", "\n")), caPubA);
		in.close();
		
		in = new Scanner(pubF);
		String pubA = in.nextLine();
		String pubV = in.nextLine().replaceAll("&l", "\n");
		PublicKey pubK = ASymmetric.getPublicKeyFromByteArray(Base64.decode(pubV), pubA);
		in.close();
		in = new Scanner(privF);
		String privA = in.nextLine();
		PrivateKey privK = ASymmetric.getPrivateKeyFromByteArray(Base64.decode(in.nextLine().replaceAll("&l", "\n")), privA);
		in.close();
		this.localKey = new KeyPair(pubK,privK);
		
		in = new Scanner(sigF);
		this.signature = new Signature(in.nextLine());
		in.close();
	}
	public PublicKey getCaKey() {
		return caKey;
	}
	public KeyPair getLocalKey() {
		return localKey;
	}
	public Signature getSignature() {
		return signature;
	}
	
}
