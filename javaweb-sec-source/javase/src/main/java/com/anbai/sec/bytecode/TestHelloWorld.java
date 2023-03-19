package com.anbai.sec.bytecode;

import java.io.Serializable;

/**
 * Creator: yz
 * Date: 2019/12/17
 */
@Deprecated
public class TestHelloWorld implements Serializable {

	private static final long serialVersionUID = -7366591802115333975L;

	private long id = 1L;

	private String username;

	private String password;

	public String hello(String content) {
		String str = "Hello:";
		return str + content;
	}

	public static void main(String[] args) {
		TestHelloWorld test = new TestHelloWorld();
		String         str  = test.hello("Hello World~");

		System.out.println(str);
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String toString() {
		return "TestHelloWorld{" +
				"id=" + id +
				", username='" + username + '\'' +
				", password='" + password + '\'' +
				'}';
	}

}