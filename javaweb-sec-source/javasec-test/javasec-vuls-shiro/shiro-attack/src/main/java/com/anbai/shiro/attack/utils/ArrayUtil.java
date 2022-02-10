package com.anbai.shiro.attack.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author su18
 */
public class ArrayUtil {
	/**
	 * 拼接字节到字节数组中
	 *
	 * @param paramArrayOfByte 原始字节数组
	 * @param paramByte        要拼接的字节
	 * @return 拼接后的数组
	 */
	public static byte[] mergerArray(byte[] paramArrayOfByte, byte paramByte) {
		byte[] arrayOfByte = new byte[paramArrayOfByte.length + 1];
		System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, paramArrayOfByte.length);
		arrayOfByte[paramArrayOfByte.length] = paramByte;
		return arrayOfByte;
	}

	/**
	 * 两个字节数组拼接
	 *
	 * @param paramArrayOfByte1 字节数组1
	 * @param paramArrayOfByte2 字节数组2
	 * @return 拼接后的数组
	 */
	public static byte[] mergerArray(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) {
		byte[] arrayOfByte = new byte[paramArrayOfByte1.length + paramArrayOfByte2.length];
		System.arraycopy(paramArrayOfByte1, 0, arrayOfByte, 0, paramArrayOfByte1.length);
		System.arraycopy(paramArrayOfByte2, 0, arrayOfByte, paramArrayOfByte1.length, paramArrayOfByte2.length);
		return arrayOfByte;
	}

	/**
	 * 字节数组拆分
	 *
	 * @param paramArrayOfByte 原始数组
	 * @param paramInt1        起始下标
	 * @param paramInt2        要截取的长度
	 * @return 处理后的数组
	 */
	public static byte[] subArray(byte[] paramArrayOfByte, int paramInt1, int paramInt2) {
		byte[] arrayOfByte = new byte[paramInt2];
		int i = 0;
		while (true) {
			if (i >= paramInt2)
				return arrayOfByte;
			arrayOfByte[i] = paramArrayOfByte[(i + paramInt1)];
			i += 1;
		}
	}

	/**
	 * int数组转byte数组
	 *
	 * @param paramArrayOfInt int数组
	 * @return 转换后的byte数组
	 */
	public static byte[] intsToBytes(int[] paramArrayOfInt) {
		byte[] arrayOfByte = new byte[paramArrayOfInt.length];
		int i = 0;
		while (true) {
			if (i >= paramArrayOfInt.length)
				return arrayOfByte;
			arrayOfByte[i] = (byte) paramArrayOfInt[i];
			i += 1;
		}
	}

	/**
	 * 字符串转byte数组
	 *
	 * @param paramString 字符串
	 * @param paramInt    字符串数组长度
	 * @return 转换后的数组
	 */
	public static byte[] stringToBytes(String paramString, int paramInt) {
		while (true) {
			if (paramString.getBytes().length >= paramInt)
				return paramString.getBytes();
			paramString = paramString + " ";
		}
	}

	/**
	 * 分割字节数组
	 *
	 * @param bytes 待分割的字节数组
	 * @param size  分割大小
	 * @return 分割后的二维数组
	 */
	public static byte[][] splitBytes(byte[] bytes, int size) {
		double splitLength = Double.parseDouble(size + "");
		int arrayLength = (int) Math.ceil(bytes.length / splitLength);
		byte[][] result = new byte[arrayLength][];
		int from, to;
		for (int i = 0; i < arrayLength; i++) {
			from = (int) (i * splitLength);
			to = (int) (from + splitLength);
			if (to > bytes.length)
				to = bytes.length;
			result[i] = Arrays.copyOfRange(bytes, from, to);
		}
		return result;
	}

	/**
	 * 二维字节数组反转
	 *
	 * @param bytes 需要反转的二维字节数组
	 * @return 反转后的二维字节数组
	 */
	public static byte[][] reverseTwoDimensionalBytesArray(byte[][] bytes) {
		List<byte[]> list = Arrays.asList(bytes);
		Collections.reverse(list);
		return (byte[][]) list.toArray();
	}

	/**
	 * byte[] to hex string
	 *
	 * @param bytes
	 * @return
	 */
	public static String bytesToHex(byte[] bytes) {
		char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5',
				'6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		char[] buf = new char[bytes.length * 2];
		int index = 0;
		for (byte b : bytes) {
			buf[index++] = HEX_CHAR[b >>> 4 & 0xf];
			buf[index++] = HEX_CHAR[b & 0xf];
		}
		return new String(buf);
	}

	/**
	 * hex to byte[]
	 * @param s
	 * @return
	 */
	public static byte[] hexToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
