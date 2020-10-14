package xyz.finlaym.serverstatus;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.SecretKey;

import xyz.finlaym.serverstatus.client.ClientConnectionManager;
import xyz.finlaym.serverstatus.common.KeyManager;
import xyz.finlaym.serverstatus.daemon.StatusServer;
import xyz.finlaym.serverstatus.helper.ASymmetric;
import xyz.finlaym.serverstatus.helper.BASE64;
import xyz.finlaym.serverstatus.helper.Symmetric;

public class Main {

	public static void main(String[] args) throws Exception{
		if(args.length != 0) {
			if(args[0].equalsIgnoreCase("--init")) {
				Scanner in = new Scanner(System.in);
				System.out.print("Create CA, create keypair, or sign keys? (ca/key/sign) ");
				String response = in.nextLine();
				if(response.equalsIgnoreCase("ca")) {
					System.out.print("Private key file: ");
					File priv = new File(in.nextLine());
					System.out.print("Public key file: ");
					File pub = new File(in.nextLine());
					System.out.print("Password: ");
					String password = in.nextLine();
					System.out.print("Confirm password: ");
					if(!password.equals(in.nextLine())) {
						System.err.println("Passwords do not match!");
						in.close();
						return;
					}
					System.out.print("Generating keys... ");
					KeyPair pair = ASymmetric.genKeys(ASymmetric.RSA, 8192);
					System.out.println("Finished");
					
					priv.delete();
					priv.createNewFile();
					PrintWriter out = new PrintWriter(new FileWriter(priv,true));
					String privS = pair.getPrivate().getAlgorithm()+":"+BASE64.encode(pair.getPrivate().getEncoded());
					
					SecureRandom rand = new SecureRandom();
					rand.setSeed(System.nanoTime());
					byte[] salt = new byte[16];
					rand.nextBytes(salt);
					
					SecretKey pwKey = Symmetric.genKey(password, salt, 256, Symmetric.AES);
					
					out.println(Symmetric.AES);
					out.println(BASE64.encode(salt).replaceAll("\n", "&l"));
					out.println(256);
					out.println(Symmetric.encrypt(privS, pwKey, pwKey.getAlgorithm()));
					
					out.close();
					
					pub.delete();
					pub.createNewFile();
					out = new PrintWriter(new FileWriter(pub,true));
					out.println(pair.getPublic().getAlgorithm());
					out.println(BASE64.encode(pair.getPublic().getEncoded()).replaceAll("\n", "&l"));
					out.close();
					
					System.out.println("Successfully wrote CA keys to disk!");
					in.close();
					return;
				}else if(response.equalsIgnoreCase("key")) {
					System.out.print("Private key file: ");
					File priv = new File(in.nextLine());
					System.out.print("Public key file: ");
					File pub = new File(in.nextLine());
					
					System.out.print("Generating keys... ");
					KeyPair pair = ASymmetric.genKeys(ASymmetric.RSA, 4096);
					System.out.println("Finished");
					
					priv.delete();
					priv.createNewFile();
					PrintWriter out = new PrintWriter(new FileWriter(priv,true));
					out.println(pair.getPrivate().getAlgorithm());
					out.println(BASE64.encode(pair.getPrivate().getEncoded()).replaceAll("\n", "&l"));
					out.close();
					
					pub.delete();
					pub.createNewFile();
					out = new PrintWriter(new FileWriter(pub,true));
					out.println(pair.getPublic().getAlgorithm());
					out.println(BASE64.encode(pair.getPublic().getEncoded()).replaceAll("\n", "&l"));
					out.close();
					
					
					System.out.println("Wrote keys to disk!");
					in.close();
					return;
				}else if(response.equalsIgnoreCase("sign")) {
					System.out.print("Public key file: ");
					File pubKeyF = new File(in.nextLine());
					System.out.print("CA private key file: ");
					File caKeyF = new File(in.nextLine());
					System.out.print("CA passphrase: ");
					String password = in.nextLine();
					System.out.print("Output file: ");
					File outputF = new File(in.nextLine());
					
					Scanner fin = new Scanner(pubKeyF);
					String pubKeyS = fin.nextLine()+":"+fin.nextLine();
					
					fin.close();
					
					fin = new Scanner(caKeyF);
					String caPAlgo = fin.nextLine();
					byte[] caPSalt = BASE64.decode(fin.nextLine().replaceAll("&l", "\n"));
					int caPLength = Integer.valueOf(fin.nextLine());
					SecretKey caPKey = Symmetric.genKey(password, caPSalt, caPLength, caPAlgo);
					
					String caPrivS;
					try {
						caPrivS = Symmetric.decrypt(fin.nextLine(), caPKey, caPKey.getAlgorithm());
					}catch(Exception e) {
						System.err.println("Incorrect password!");
						fin.close();
						return;
					}
					fin.close();
					String[] caPrivSS = caPrivS.split(":",2);
					PrivateKey caPriv = ASymmetric.getPrivateKeyFromByteArray(BASE64.decode(caPrivSS[1]), caPrivSS[0]);
					
					String signedPubKey = ASymmetric.sign(pubKeyS, caPriv, caPriv.getAlgorithm());
					
					outputF.delete();
					outputF.createNewFile();
					
					PrintWriter out = new PrintWriter(new FileWriter(outputF,true));
					out.println(signedPubKey);
					out.close();
					
					System.out.println("Successfully signed public key!");
					in.close();
					return;
				}else {
					System.out.println("Invalid response!");
					in.close();
					return;
				}
			}
		}
		KeyManager kManager = new KeyManager(new File("ca.pub"), new File("local.priv"), new File("local.pub"), new File("local.sig"));
		StatusServer sServer = new StatusServer(kManager);
		sServer.start();
		@SuppressWarnings("resource")
		Scanner in = new Scanner(System.in);
		ClientConnectionManager ccm = new ClientConnectionManager(kManager, "localhost");
		while(true) {
			System.out.print("> ");
			String cmd = in.nextLine();
			if(cmd.equalsIgnoreCase("ping")) {
				ccm.ping();
			}
		}
	}
}
