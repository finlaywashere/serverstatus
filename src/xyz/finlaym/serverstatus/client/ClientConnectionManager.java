package xyz.finlaym.serverstatus.client;

import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.SecretKey;

import xyz.finlaym.serverstatus.common.KeyManager;
import xyz.finlaym.serverstatus.common.Signature;
import xyz.finlaym.serverstatus.daemon.StatusServer;
import xyz.finlaym.serverstatus.helper.ASymmetric;
import xyz.finlaym.serverstatus.helper.BASE64;
import xyz.finlaym.serverstatus.helper.Symmetric;

public class ClientConnectionManager {
	private SecretKey sKey;
	private Socket s;
	private Scanner in;
	private PrintWriter out;
	private boolean connected = false;
	public ClientConnectionManager(KeyManager kManager, String ip) throws Exception{
		this.s = new Socket(ip,StatusServer.PORT);
		this.out = new PrintWriter(s.getOutputStream(),true);
		this.in = new Scanner(s.getInputStream());
		
		int nonce = Integer.valueOf(in.nextLine());
		
		PublicKey localPub = kManager.getLocalKey().getPublic();
		String localPubS = localPub.getAlgorithm()+":"+BASE64.encode(localPub.getEncoded());
		out.println(localPubS.replaceAll("\n", "&l"));
		out.println(kManager.getSignature());
		out.println(ASymmetric.sign(String.valueOf(nonce), kManager.getLocalKey().getPrivate(), kManager.getLocalKey().getPrivate().getAlgorithm()));
		
		boolean success = Boolean.valueOf(in.nextLine());
		
		if(!success) {
			System.out.println("Server denied authentication!");
			in.close();
			out.close();
			s.close();
			return;
		}
		SecureRandom rand = new SecureRandom();
		rand.setSeed(System.nanoTime());
		nonce = rand.nextInt(Integer.MAX_VALUE);
		
		out.println(nonce);
		
		String remotePubS = in.nextLine();
		String[] remotePubSS = remotePubS.split(":",2);
		PublicKey remotePub = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(remotePubSS[1]), remotePubSS[0]);
		Signature caSig = new Signature(in.nextLine());
		Signature nonceSig = new Signature(in.nextLine());
		
		if(!caSig.check(remotePubS, kManager.getCaKey())) {
			// CA signature is not a match!
			// Deny
			System.out.println("Remote device failed CA signature authentication check!");
			out.println(false);
			in.close();
			out.close();
			s.close();
			return;
		}
		
		if(!nonceSig.check(String.valueOf(nonce), remotePub)) {
			// Nonce signature is not a match!
			// Deny
			System.out.println("Remote device failed nonce authentication check!");
			out.println(false);
			in.close();
			out.close();
			s.close();
			return;
		}
		out.println(true);
		
		String tmpPubS = ASymmetric.decrypt(in.nextLine(), kManager.getLocalKey().getPrivate(), kManager.getLocalKey().getPrivate().getAlgorithm());
		String[] tmpPubSS = tmpPubS.split(":",2);
		PublicKey tmpPub = ASymmetric.getPublicKeyFromByteArray(BASE64.decode(tmpPubSS[1]), tmpPubSS[0]);
		
		this.sKey = Symmetric.genKey(Symmetric.AES, 256);
		String sKeyS = this.sKey.getAlgorithm()+":"+BASE64.encode(this.sKey.getEncoded());
		out.println(ASymmetric.encrypt(sKeyS, tmpPub, tmpPub.getAlgorithm()));
		connected = true;
	}
	public boolean isConnected() {
		return connected;
	}
	public boolean ping() throws Exception{
		out.println(Symmetric.encrypt("ping", this.sKey, this.sKey.getAlgorithm()));
		String response = Symmetric.decrypt(in.nextLine(), this.sKey, this.sKey.getAlgorithm());
		return response.equals("pong");
	}
}
