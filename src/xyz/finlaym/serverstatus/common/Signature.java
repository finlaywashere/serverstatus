package xyz.finlaym.serverstatus.common;

import java.security.PublicKey;

import xyz.finlaym.serverstatus.helper.ASymmetric;

public class Signature {
	private String value;
	public String getValue() {
		return value;
	}
	public Signature(String value) {
		this.value = value;
	}
	@Override
	public String toString() {
		return value;
	}
	public boolean check(String expected, PublicKey signingKey){
		try {
			return ASymmetric.getSigned(getValue(), signingKey, signingKey.getAlgorithm()).equals(expected);
		}catch(Exception e) {
			return false;
		}
	}
}
