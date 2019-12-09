package com.anbai.sec.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author yz
 */
public class FileNullBytes {

	public static void main(String[] args) {
		try {
			String           fileName = "/tmp/null-bytes.txt\u0000.jpg";
			FileOutputStream fos      = new FileOutputStream(new File(fileName));
			fos.write("Test".getBytes());
			fos.flush();
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}