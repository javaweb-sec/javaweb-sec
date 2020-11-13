package com.anbai.sec.utils;

import java.util.Arrays;

public class ByteUtils {

	public static byte[] replaceBytes(byte[] classBuffer, String findCommand, String command) {
		// 将类字节码转换成byte字符串
		String bufferStr = Arrays.toString(classBuffer);

		bufferStr = bufferStr.replace("[", "").replace("]", "");

		// 查找需要替换的Java二进制内容
		byte[] findBytes = findCommand.getBytes();

		// 把搜索的字符串byte转换成byte字符串
		String findStr = Arrays.toString(findBytes).replace("[", "").replace("]", "");

		// 二进制替换后的byte值，注意这个值需要和替换的字符串长度一致，不然会破坏常量池
		byte[] replaceBytes = command.getBytes();

		// 把替换的字符串byte转换成byte字符串
		String replaceStr = Arrays.toString(replaceBytes).replace("[", "").replace("]", "");

		bufferStr = bufferStr.replace(findStr, replaceStr);

		// 切割替换后的byte字符串
		String[] byteArray = bufferStr.split("\\s*,\\s*");

		// 创建新的byte数组，存储替换后的二进制
		byte[] bytes = new byte[byteArray.length];

		// 将byte字符串转换成byte
		for (int i = 0; i < byteArray.length; i++) {
			bytes[i] = Byte.parseByte(byteArray[i]);
		}

		return bytes;
	}

}
