package com.anbai.sec.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FilesReadDemo {

	public static void main(String[] args) {
		// 通过File对象定义读取的文件路径
//		File file  = new File("/etc/passwd");
//		Path path1 = file.toPath();

		// 定义读取的文件路径
		Path path = Paths.get("/etc/passwd");

		try {
			byte[] bytes = Files.readAllBytes(path);
			System.out.println(new String(bytes));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
