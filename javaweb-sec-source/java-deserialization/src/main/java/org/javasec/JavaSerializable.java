package org.javasec;

import javax.naming.NamingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class JavaSerializable {


	public String getSerializableToBase64String(Object object) throws IOException {
		return new sun.misc.BASE64Encoder().encode(this.getSerializableToByte(object));
	}

	public byte[] getSerializableToByte(Object object) throws IOException {

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		ObjectOutputStream    objectOutputStream    = new ObjectOutputStream(byteArrayOutputStream);

		objectOutputStream.writeObject(object);
		return byteArrayOutputStream.toByteArray();
	}

	public static void main(String[] args) throws IOException, NamingException {
		JavaSerializable javaSerializable = new JavaSerializable();

		String ser = javaSerializable.getSerializableToBase64String(new TestSer());

		System.out.println(ser);
	}
}
