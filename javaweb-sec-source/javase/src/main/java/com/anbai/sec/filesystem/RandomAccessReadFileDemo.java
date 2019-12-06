package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class RandomAccessReadFileDemo {

	public static void main(String[] args) {
		File file = new File("/etc/passwd");

		try {
			// 创建RandomAccessFile对象,r表示以只读模式打开文件，一共有:r(只读)、rw(读写)、
			// rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
			RandomAccessFile raf = new RandomAccessFile(file, "r");

			// 定义每次输入流读取到的字节数对象
			int a = 0;

			// 定义缓冲区大小
			byte[] bytes = new byte[1024];

			// 创建二进制输出流对象
			ByteArrayOutputStream out = new ByteArrayOutputStream();

			// 循环读取文件内容
			while ((a = raf.read(bytes)) != -1) {
				// 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
				// 下标0开始截取，a表示输入流read到的字节数。
				out.write(bytes, 0, a);
			}

			System.out.println(out.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
