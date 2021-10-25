//package com.anbai.sec.classloader;
//
//import java.io.IOException;
//
//public class TestBCELClass {
//
//	static {
//		String command = "open -a Calculator.app";
//		String osName  = System.getProperty("os.name");
//
//		if (osName.startsWith("Windows")) {
//			command = "calc 12345678901234567";
//		} else if (osName.startsWith("Linux")) {
//			command = "curl localhost:9999/";
//		}
//
//		try {
//			Runtime.getRuntime().exec(command);
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//	}
//
//}