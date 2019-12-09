package org.javasec;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class JavaDeserializable {


	public Object getUnSerializableObject(String base64) throws Exception {
		byte[] objectByte = new sun.misc.BASE64Decoder().decodeBuffer(base64);
		return this.getUnSerializableObject(objectByte);
	}

	public Object getUnSerializableObject(byte[] objectByte) throws Exception {

		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objectByte);
		ObjectInputStream    objectInputStream    = new ObjectInputStream(byteArrayInputStream);
		return objectInputStream.readObject();
	}

	public static void main(String[] args) throws Exception {
		JavaDeserializable javaUnSer = new JavaDeserializable();

		// 待实例的类 类名 = javaUnSerializable.getUnSerializableObject("");
		// 类名.method();

		// 获取序列化对象字节码
		String getParameter = "rO0ABXNyABdvcmcuamF2YXNlYy5UZXN0UnVuVGltZdTws4isweFuAgAAeHA=";

		// 初始化 org.javasec.TestSer 父类 InitialContext
//		InitialContext initialContext = (InitialContext) javaUnSer.getUnSerializableObject(getParameter);

		// 调用重写后的 composeName 方法，执行命令
//		String result = initialContext.composeName("whoami", "");


		Test result = (Test) javaUnSer.getUnSerializableObject(getParameter);

		System.out.println(result.getSource("ls"));
	}
}
