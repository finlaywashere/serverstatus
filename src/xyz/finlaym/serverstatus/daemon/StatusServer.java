package xyz.finlaym.serverstatus.daemon;

import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.SecretKey;

import xyz.finlaym.serverstatus.common.KeyManager;
import xyz.finlaym.serverstatus.common.Signature;
import xyz.finlaym.serverstatus.helper.ASymmetric;
import xyz.finlaym.serverstatus.helper.BASE64;
import xyz.finlaym.serverstatus.helper.Symmetric;

public class StatusServer extends Thread{
	private static final int PORT = 8888;
	
	private KeyManager kManager;
	public StatusServer(KeyManager kManager){
		this.kManager = kManager;
	}
	public void run(){
		try {
			ServerSocket ss = new ServerSocket(PORT);
			while(!ss.isClosed()) {
				try {
					Socket s = ss.accept();
					StatusThread thread = new StatusThread(s);
					thread.start();
				}catch(Exception e) {
					e.printStackTrace();
				}
			}
			ss.close();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
	private class StatusThread extends Thread{
		private Socket s;
		public StatusThread(Socket s) {
			this.s = s;
		}
		@Override
		public void run() {
			try {
				System.out.println("Received connection from "+s.getInetAddress().toString());
				PrintWriter out = new PrintWriter(s.getOutputStream(),true);
				Scanner in = new Scanner(s.getInputStream());
				SecureRandom rand = new SecureRandom();
				rand.setSeed(System.nanoTime());
				int nonce = rand.nextInt(Integer.MAX_VALUE);
				
				out.println(nonce);
				
				String remotePubS = in.nextLine().replaceAll("&l", "\n");
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
				System.out.println("Remote device passed authentication check!");
				
				nonce = Integer.valueOf(in.nextLine());
				PublicKey localPub = kManager.getLocalKey().getPublic();
				String localPubS = localPub.getAlgorithm()+":"+BASE64.encode(localPub.getEncoded());
				out.println(localPubS);
				out.println(kManager.getSignature().toString());
				out.println(ASymmetric.sign(String.valueOf(nonce), kManager.getLocalKey().getPrivate(), kManager.getLocalKey().getPrivate().getAlgorithm()));
				
				boolean success = Boolean.valueOf(in.nextLine());
				
				if(!success) {
					System.out.println("Remote server denied our authentication!");
					in.close();
					out.close();
					s.close();
					return;
				}
				System.out.println("Sucessfully authenticated with remote server!");
				
				// Generate a new keypair for the key exchange to do PFS
				KeyPair tmpPair = ASymmetric.genKeys(ASymmetric.RSA, 4096);
				String pubS = tmpPair.getPublic().getAlgorithm()+":"+BASE64.encode(tmpPair.getPublic().getEncoded());
				
				out.println(ASymmetric.encrypt(pubS, remotePub, remotePub.getAlgorithm()));
				
				String[] keyS = ASymmetric.decrypt(in.nextLine(), tmpPair.getPrivate(), tmpPair.getPrivate().getAlgorithm()).split(":",2);
				SecretKey sKey = Symmetric.genKeyFromByteArray(BASE64.decode(keyS[1]), keyS[0]);
				
				// Now we're encrypted and authenticated!
				
				while(!s.isClosed()) {
					String[] cmd = Symmetric.decrypt(in.nextLine(),sKey,sKey.getAlgorithm()).split(" ");
					String cmdS = cmd[0].toLowerCase();
					if(cmdS.equals("ping")) {
						out.println(Symmetric.encrypt("pong", sKey, sKey.getAlgorithm()));
						continue;
					}
					
				}
				
				in.close();
				out.close();
				s.close();
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
	}
}
