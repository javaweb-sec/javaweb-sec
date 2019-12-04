package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileInputStreamDemo {

	public static void main(String[] args) throws IOException {
		File file = new File("/etc/passwd");

		// 打开文件对象并创建文件输入流
		FileInputStream fis = new FileInputStream(file);

		// 定义每次输入流读取到的字节数对象
		int a = 0;

		// 定义缓冲区大小
		byte[] bytes = new byte[1024];

		// 创建二进制输出流对象
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// 循环读取文件内容
		while ((a = fis.read(bytes)) != -1) {
			// 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
			// 下标0开始截取，a表示输入流read到的字节数。
			out.write(bytes, 0, a);
		}

		System.out.println(out.toString());
	}

}
