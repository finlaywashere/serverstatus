package xyz.finlaym.serverstatus.helper;

import java.io.IOException;
import java.util.Base64;

public class BASE64 {
	
	public static byte[] decode(String s) throws IOException{
		return Base64.getDecoder().decode(s);
	}
	public static String encode(byte[] b){
		return Base64.getEncoder().encodeToString(b);
	}
}
