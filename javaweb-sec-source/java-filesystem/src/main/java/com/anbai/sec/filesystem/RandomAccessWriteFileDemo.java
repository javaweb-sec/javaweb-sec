package com.anbai.sec.filesystem;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class RandomAccessWriteFileDemo {

	public static void main(String[] args) {
		File file = new File("/tmp/test.txt");

		// 定义待写入文件内容
		String content = "Hello World.";

		try {
			// 创建RandomAccessFile对象,rw表示以读写模式打开文件，一共有:r(只读)、rw(读写)、
			// rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
			RandomAccessFile raf = new RandomAccessFile(file, "rw");

			// 写入内容二进制到文件
			raf.write(content.getBytes());
			raf.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
