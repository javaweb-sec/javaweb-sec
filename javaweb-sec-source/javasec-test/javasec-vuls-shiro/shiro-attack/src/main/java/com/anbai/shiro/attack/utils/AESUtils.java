package com.anbai.shiro.attack.utils;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.CipherService;
import org.apache.shiro.util.ByteSource;

/**
 * @author su18
 */
public class AESUtils {

	public CipherService cipherService = new AesCipherService();

	public final byte[] DEFAULT_CIPHER_KEY_BYTES;

	public AESUtils(String aesKey) {
		this.DEFAULT_CIPHER_KEY_BYTES = Base64.decode(aesKey);
	}

	public byte[] decrypt(byte[] encrypted) {
		byte[]     serialized;
		ByteSource byteSource = cipherService.decrypt(encrypted, DEFAULT_CIPHER_KEY_BYTES);
		serialized = byteSource.getBytes();
		return serialized;
	}

	public byte[] encrypt(byte[] serialized) {
		byte[]     value;
		ByteSource byteSource = cipherService.encrypt(serialized, DEFAULT_CIPHER_KEY_BYTES);
		value = byteSource.getBytes();
		return value;
	}


}