package com.anbai.sec.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileOutputStreamDemo {

	public static void main(String[] args) throws IOException {
		// 定义写入文件路径
		File file = new File("/tmp/1.txt");

		// 定义待写入文件内容
		String content = "Hello World.";

		// 创建FileOutputStream对象
		FileOutputStream fos = new FileOutputStream(file);

		// 写入内容二进制到文件
		fos.write(content.getBytes());
		fos.flush();
		fos.close();
	}

}
