package com.anbai.sec.axis;

/**
 * @author yz
 */
public class TestService {

	public String hello(String str) {
		System.out.println(str);
		return "Hello World!";
	}

	public String hi(String str) {
		return str;
	}

}
