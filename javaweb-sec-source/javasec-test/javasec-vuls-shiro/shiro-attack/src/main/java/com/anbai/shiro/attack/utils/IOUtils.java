package com.anbai.shiro.attack.utils;

import java.io.*;

/**
 * @author su18
 */
public class IOUtils {

	public static byte[] getFileToByte(File file) {
		byte[]      by = new byte[(int) file.length()];
		InputStream is =null;
		try {
			is = new FileInputStream(file);
			ByteArrayOutputStream bytestream = new ByteArrayOutputStream();
			byte[]                bb         = new byte[2048];
			int ch;
			ch = is.read(bb);
			while (ch != -1) {
				bytestream.write(bb, 0, ch);
				ch = is.read(bb);
			}
			by = bytestream.toByteArray();
		} catch (Exception ex) {
			ex.printStackTrace();
		}finally {
			try {
				is.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return by;
	}

}
