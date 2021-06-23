// Crypto example to compare Java results against a Python implementation
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;
import java.security.SecureRandom;

import java.util.Arrays;

public class KeyGeneratorExample {
	public static void main(String args[]) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		Key key = keyGen.generateKey();
		System.out.println(key.getEncoded().length);

		byte[] bytes = new byte[32];
		Arrays.fill(bytes, (byte) 0);
		SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, "AES");

		byte[] iv = new byte[16];
		Arrays.fill(iv, (byte) 0);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		System.out.println(key);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		// cipher.init(cipher.ENCRYPT_MODE, key);
		// cipher.init(cipher.ENCRYPT_MODE, secretKeySpec);
		cipher.init(cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

		String msg = new String("12345678");
		System.out.println(msg.length());
		System.out.println(msg.getBytes("UTF-8").length);
		bytes = cipher.doFinal(msg.getBytes("UTF-8"));
		System.out.println(bytes.length);

		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		System.out.println(sb.toString());
	}
}
