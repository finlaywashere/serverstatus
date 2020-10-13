package xyz.finlaym.serverstatus.daemon;

import java.net.ServerSocket;

public class StatusServer extends Thread{
	private static final int PORT = 8888;
	
	public StatusServer() {
		start();
	}
	@Override
	public void run() {
		try {
			ServerSocket ss = new ServerSocket(PORT);
		}catch(Exception e) {
			e.printStackTrace();
		}
	}
}
