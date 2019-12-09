package org.javasec;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

public class TestRunTime extends Test implements Serializable {

	@Override
	public String getSource(String c) throws IOException {
		StringBuilder stringBuffer = new StringBuilder();

//		try {
//			Process     process     = Runtime.getRuntime().exec(c);
//			InputStream inputStream = process.getInputStream();
//			int         chr         = 0;
//
//			while ((chr = inputStream.read()) != -1) {
//				stringBuffer.append((char) chr);
//			}
//		} catch (IOException ignored) {
//		}
		return stringBuffer.toString();
	}
}