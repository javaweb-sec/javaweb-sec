package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class DeserializationTest implements Serializable {

	private String username;

	private String email;

	public DeserializationTest() {
		System.out.println("init...");
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public static void main(String[] args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			// 创建DeserializationTest类，并类设置属性值
			DeserializationTest t = new DeserializationTest();
			t.setUsername("yz");
			t.setEmail("admin@javaweb.org");

			// 创建Java对象序列化输出流对象
			ObjectOutputStream out = new ObjectOutputStream(baos);

			// 序列化DeserializationTest类
			out.writeObject(t);
			out.flush();
			out.close();

			// 打印DeserializationTest类序列化以后的字节数组，我们可以将其存储到文件中或者通过Socket发送到远程服务地址
			System.out.println("DeserializationTest类序列化后的字节数组:" + Arrays.toString(baos.toByteArray()));

			// 利用DeserializationTest类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

			// 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 反序列化输入流数据为DeserializationTest对象
			DeserializationTest test = (DeserializationTest) in.readObject();
			System.out.println("用户名:" + test.getUsername() + ",邮箱:" + test.getEmail());

			// 关闭ObjectInputStream输入流
			in.close();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

}