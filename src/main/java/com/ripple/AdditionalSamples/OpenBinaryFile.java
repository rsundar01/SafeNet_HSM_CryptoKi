package com.ripple.AdditionalSamples;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Base64;

public class OpenBinaryFile {

	public static void main(String[] args) throws IOException {
		RandomAccessFile f = new RandomAccessFile(new File("wrapped.key"), "r");
		byte[] b = new byte[(int)f.length()];
		f.readFully(b);
		System.out.println("value of the encrypted file fromLunaCm ="+ bytesToHex(b));

		f = new RandomAccessFile(new File("publickey.bin"), "r");
		b = new byte[(int)f.length()];
		f.readFully(b);
		System.out.println("value of the public key from ckdemo ="+ bytesToHex(b));
		
		f = new RandomAccessFile(new File("ed25519key.txt"), "r");
		b = new byte[(int)f.length()];
		String readLine = f.readLine();

		byte[] decoded = Base64.getDecoder().decode(readLine);
	    System.out.println("value of the ed25519key.pem2 = "+ bytesToHex(decoded));
		



	
		
		
	}
	
	
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

}
