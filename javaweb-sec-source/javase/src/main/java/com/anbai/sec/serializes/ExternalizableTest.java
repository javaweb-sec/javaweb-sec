package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class ExternalizableTest implements java.io.Externalizable {

	private String username;

	private String email;

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

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeObject(username);
		out.writeObject(email);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		this.username = (String) in.readObject();
		this.email = (String) in.readObject();
	}

	public static void main(String[] args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			// 创建ExternalizableTest类，并类设置属性值
			ExternalizableTest t = new ExternalizableTest();
			t.setUsername("yz");
			t.setEmail("admin@javaweb.org");

			ObjectOutputStream out = new ObjectOutputStream(baos);
			out.writeObject(t);
			out.flush();
			out.close();

			// 打印ExternalizableTest类序列化以后的字节数组，我们可以将其存储到文件中或者通过Socket发送到远程服务地址
			System.out.println("ExternalizableTest类序列化后的字节数组:" + Arrays.toString(baos.toByteArray()));
			System.out.println("ExternalizableTest类反序列化后的字符串:" + new String(baos.toByteArray()));

			// 利用DeserializationTest类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

			// 通过反序列化输入流创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 反序列化输入流数据为ExternalizableTest对象
			ExternalizableTest test = (ExternalizableTest) in.readObject();
			System.out.println("用户名:" + test.getUsername() + ",邮箱:" + test.getEmail());

			// 关闭ObjectInputStream输入流
			in.close();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

}
