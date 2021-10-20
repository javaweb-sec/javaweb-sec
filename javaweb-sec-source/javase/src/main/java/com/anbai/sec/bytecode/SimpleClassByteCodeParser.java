package com.anbai.sec.bytecode;

import com.alibaba.fastjson.JSON;
import org.javaweb.utils.EncryptUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SimpleClassByteCodeParser {

	/**
	 * 转换为数据输入流
	 */
	private DataInputStream dis;

	/**
	 * 解析Class字节码
	 *
	 * @param in 类字节码输入流
	 * @throws IOException 解析IO异常
	 */
	private Map<String, Object> parseByteCode(InputStream in) throws IOException {
		Map<String, Object> byteCodeMap = new LinkedHashMap<>();

		this.dis = new DataInputStream(in);

		// u4 magic;
		int magic = dis.readInt();

		// 校验文件魔数
		if (0xCAFEBABE == magic) {
			byteCodeMap.put("magic", magic);

			// u2 minor_version
			byteCodeMap.put("minor", dis.readUnsignedShort());

			// u2 major_version;
			byteCodeMap.put("major", dis.readUnsignedShort());

			// 解析常量池数据
			Map<Integer, Map<String, Object>> constantPoolMap = parseConstantPool();

			byteCodeMap.put("constantPoolMap", constantPoolMap);

			// u2 access_flags;
			byteCodeMap.put("accessFlags", dis.readUnsignedShort());

			// u2 this_class;
			byteCodeMap.put("thisClass", getConstantPoolValue(dis.readUnsignedShort(), "nameValue", constantPoolMap));

			// u2 super_class;
			int superClassIndex = dis.readUnsignedShort();

			// 当解析Object类的时候super_class为0
			if (superClassIndex != 0) {
				byteCodeMap.put("superClass", getConstantPoolValue(superClassIndex, "nameValue", constantPoolMap));
			} else {
				byteCodeMap.put("superClass", "java/lang/Object");
			}

			// u2 interfaces_count;
			int interfacesCount = dis.readUnsignedShort();
			byteCodeMap.put("interfacesCount", interfacesCount);

			// 创建接口Index数组
			String[] interfaces = new String[interfacesCount];

			// u2 interfaces[interfaces_count];
			for (int i = 0; i < interfacesCount; i++) {
				int index = dis.readUnsignedShort();

				// 设置接口名称
				interfaces[i] = (String) getConstantPoolValue(index, "nameValue", constantPoolMap);
			}

			byteCodeMap.put("interfaces", interfaces);

			// u2 fields_count;
			int fieldsCount = dis.readUnsignedShort();
			byteCodeMap.put("fieldsCount", fieldsCount);

			List<Map<String, Object>> fieldList = new ArrayList<>();

			// field_info fields[fields_count];
			for (int i = 0; i < fieldsCount; i++) {
//				field_info {
//					u2 access_flags;
//					u2 name_index;
//					u2 descriptor_index;
//					u2 attributes_count;
//					attribute_info attributes[attributes_count];
//				}

				fieldList.add(readFieldOrMethod(constantPoolMap));
			}

			byteCodeMap.put("fieldList", fieldList);

			// u2 methods_count;
			int methodsCount = dis.readUnsignedShort();
			byteCodeMap.put("methodsCount", methodsCount);

			List<Map<String, Object>> methodList = new ArrayList<>();

			// method_info methods[methods_count];
			for (int i = 0; i < methodsCount; i++) {
//				method_info {
//					u2 access_flags;
//					u2 name_index;
//					u2 descriptor_index;
//					u2 attributes_count;
//					attribute_info attributes[attributes_count];
//				}

				methodList.add(readFieldOrMethod(constantPoolMap));
			}

			byteCodeMap.put("methodList", methodList);

			// u2 attributes_count;
			int attributesCount = dis.readUnsignedShort();

			byteCodeMap.put("attributesCount", attributesCount);

			// attribute_info attributes[attributes_count];
			byteCodeMap.put("attributes", readAttributes(attributesCount, constantPoolMap));
		} else {
			throw new RuntimeException("Class文件格式错误!");
		}

		return byteCodeMap;
	}

	/**
	 * 解析常量池数据
	 *
	 * @throws IOException 数据读取异常
	 */
	private Map<Integer, Map<String, Object>> parseConstantPool() throws IOException {
		Map<Integer, Map<String, Object>> constantPoolMap = new LinkedHashMap<>();

		// u2 constant_pool_count;
		int poolCount = dis.readUnsignedShort();

		// cp_info constant_pool[constant_pool_count-1];
		for (int i = 1; i <= poolCount - 1; i++) {
			int                 tag = dis.readUnsignedByte();
			Map<String, Object> map = new LinkedHashMap<>();

			if (tag == 1) {
//				CONSTANT_Utf8_info {
//					u1 tag;
//					u2 length;
//					u1 bytes[length];
//				}

				int    length = dis.readUnsignedShort();
				byte[] bytes  = new byte[length];
				dis.read(bytes);

				map.put("tag", "CONSTANT_UTF8");
				map.put("value", new String(bytes, UTF_8));
			} else if (tag == 3) {
//				CONSTANT_Integer_info {
//					u1 tag;
//					u4 bytes;
//				}

				map.put("tag", "CONSTANT_INTEGER");
				map.put("value", dis.readInt());
			} else if (tag == 4) {
//				CONSTANT_Float_info {
//					u1 tag;
//					u4 bytes;
//				}

				map.put("tag", "CONSTANT_FLOAT");
				map.put("value", dis.readFloat());
			} else if (tag == 5) {
//				CONSTANT_Long_info {
//					u1 tag;
//					u4 high_bytes;
//					u4 low_bytes;
//				}

				map.put("tag", "CONSTANT_LONG");
				map.put("value", dis.readLong());
			} else if (tag == 6) {
//				CONSTANT_Double_info {
//					u1 tag;
//					u4 high_bytes;
//					u4 low_bytes;
//				}

				map.put("tag", "CONSTANT_DOUBLE");
				map.put("value", dis.readDouble());
			} else if (tag == 7) {
//				CONSTANT_Class_info {
//					u1 tag;
//					u2 name_index;
//				}

				int nameIndex = dis.readUnsignedShort();

				map.put("tag", "CONSTANT_CLASS");
				map.put("nameIndex", nameIndex);
			} else if (tag == 8) {
//				CONSTANT_String_info {
//					u1 tag;
//					u2 string_index;
//				}

				int stringIndex = dis.readUnsignedShort();

				map.put("tag", "CONSTANT_STRING");
				map.put("stringIndex", stringIndex);
			} else if (tag == 9) {
//				CONSTANT_Fieldref_info {
//					u1 tag;
//					u2 class_index;
//					u2 name_and_type_index;
//				}

				map.put("tag", "CONSTANT_FIELD_REF");
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
			} else if (tag == 10) {
//				CONSTANT_Methodref_info {
//					u1 tag;
//					u2 class_index;
//					u2 name_and_type_index;
//				}

				map.put("tag", "CONSTANT_METHOD_REF");
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
			} else if (tag == 11) {
//				CONSTANT_InterfaceMethodref_info {
//					u1 tag;
//					u2 class_index;
//					u2 name_and_type_index;
//				}

				map.put("tag", "CONSTANT_INTERFACE_METHOD_REF");
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
			} else if (tag == 12) {
//				CONSTANT_NameAndType_info {
//					u1 tag;
//					u2 name_index;
//					u2 descriptor_index;
//				}

				map.put("tag", "CONSTANT_NAME_AND_TYPE");
				map.put("nameIndex", dis.readUnsignedShort());
				map.put("descriptorIndex", dis.readUnsignedShort());
			} else if (tag == 15) {
//				CONSTANT_MethodHandle_info {
//					u1 tag;
//					u1 reference_kind;
//					u2 reference_index;
//				}

				map.put("tag", "CONSTANT_METHOD_HANDLE");
				map.put("referenceKind", dis.readUnsignedByte());
				map.put("referenceIndex", dis.readUnsignedShort());
			} else if (tag == 16) {
//				CONSTANT_MethodType_info {
//					u1 tag;
//					u2 descriptor_index;
//				}

				map.put("tag", "CONSTANT_METHOD_TYPE");
				map.put("descriptorIndex", dis.readUnsignedShort());
			} else if (tag == 17) {
//				CONSTANT_Dynamic_info {
//					u1 tag;
//					u2 bootstrap_method_attr_index;
//					u2 name_and_type_index;
//				}

				map.put("tag", "CONSTANT_DYNAMIC");
				map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
			} else if (tag == 18) {
//				CONSTANT_InvokeDynamic_info {
//					u1 tag;
//					u2 bootstrap_method_attr_index;
//					u2 name_and_type_index;
//				}

				map.put("tag", "CONSTANT_INVOKE_DYNAMIC");
				map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
			} else if (tag == 19) {
//				CONSTANT_Module_info {
//					u1 tag;
//					u2 name_index;
//				}

				map.put("tag", "CONSTANT_MODULE");
				map.put("nameIndex", dis.readUnsignedShort());
			} else if (tag == 20) {
//				CONSTANT_Package_info {
//					u1 tag;
//					u2 name_index;
//				}

				map.put("tag", "CONSTANT_PACKAGE");
				map.put("nameIndex", dis.readUnsignedShort());
			}

			constantPoolMap.put(i, map);

			// Long和Double是宽类型，占两位
			if (tag == 5 || tag == 6) {
				i++;
			}
		}

		// 链接常量池中的引用
		for (Integer id : constantPoolMap.keySet()) {
			Map<String, Object> valueMap = constantPoolMap.get(id);

			if (!valueMap.containsKey("value")) {
				Map<String, Object> newMap = new LinkedHashMap<>();

				for (String key : valueMap.keySet()) {
					if (key.endsWith("Index")) {
						Object value = recursionValue((Integer) valueMap.get(key), constantPoolMap);

						if (value != null) {
							String newKey = key.substring(0, key.indexOf("Index"));

							newMap.put(newKey + "Value", value);
						}
					}
				}

				valueMap.putAll(newMap);
			}
		}

		return constantPoolMap;
	}

	/**
	 * 递归查找ID对应的常量池中的值
	 *
	 * @param id      常量池ID
	 * @param poolMap poolMap
	 * @return 常量池中存储的值
	 */
	private Object recursionValue(Integer id, Map<Integer, Map<String, Object>> poolMap) {
		Map<String, Object> map = poolMap.get(id);

		if (map.containsKey("value")) {
			return map.get("value");
		}

		for (String key : map.keySet()) {
			if (key.endsWith("Index")) {
				Integer value = (Integer) map.get(key);

				return recursionValue(value, poolMap);
			}
		}

		return null;
	}

	/**
	 * 通过常量池中的索引ID和名称获取常量池中的值
	 *
	 * @param index     索引ID
	 * @param nameValue 键名
	 * @param poolMap   poolMap
	 * @return 常量池中的值
	 */
	private Object getConstantPoolValue(int index, String nameValue, Map<Integer, Map<String, Object>> poolMap) {
		return poolMap.get(index).get(nameValue);
	}

	private Map<String, Object> readAttributes(int attrCount, Map<Integer, Map<String, Object>> poolMap) throws IOException {
		Map<String, Object> attributeMap = new LinkedHashMap<>();

		// attribute_info attributes[attributes_count];
		for (int j = 0; j < attrCount; j++) {
//			attribute_info {
//				u2 attribute_name_index;
//				u4 attribute_length;
//				u1 info[attribute_length];
//			}

			// u2 attribute_name_index;
			String attributeName = (String) getConstantPoolValue(dis.readUnsignedShort(), "value", poolMap);
			attributeMap.put("attributeName", attributeName);

			// u4 attribute_length;
			int attributeLength = dis.readInt();

			// 示例程序，只解析Code属性，其他属性一律不解析
			if ("Code".equals(attributeName)) {
//				Code_attribute {
//					u2 attribute_name_index;
//					u4 attribute_length;
//					u2 max_stack;
//					u2 max_locals;
//					u4 code_length;
//					u1 code[code_length];
//					u2 exception_table_length;
//					{ u2 start_pc;
//						u2 end_pc;
//						u2 handler_pc;
//						u2 catch_type;
//					} exception_table[exception_table_length];
//					u2 attributes_count;
//					attribute_info attributes[attributes_count];
//				}

				int   maxStack   = dis.readUnsignedShort();
				int   maxLocals  = dis.readUnsignedShort();
				int   codeLength = dis.readInt();
				int[] opCodes    = new int[codeLength];

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("maxStack", maxStack);
				attrMap.put("maxLocals", maxLocals);
				attrMap.put("codeLength", codeLength);

				for (int i = 0; i < codeLength; i++) {
					opCodes[i] = dis.readUnsignedByte();
				}

				attrMap.put("opCodes", opCodes);

				// 读取异常表
				attrMap.put("exceptionTable", readExceptionTable());

				// u2 attributes_count;
				int attributesCount = dis.readShort();
				attrMap.put("attributeLength", attributeLength);
				attrMap.put("attributes", readAttributes(attributesCount, poolMap));

				// 递归读取属性信息
				attributeMap.put("Code", attrMap);
			} else {
				byte[] bytes = new byte[attributeLength];
				dis.read(bytes);
				attributeMap.put("attributeValue", EncryptUtils.base64Encode(bytes));
			}
		}

		return attributeMap;
	}

	/**
	 * 读取异常表数据
	 *
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readExceptionTable() throws IOException {
		Map<String, Object> exceptionTable = new LinkedHashMap<>();

		int exceptionTableLength = dis.readUnsignedShort();
		exceptionTable.put("exceptionTableLength", exceptionTableLength);

		List<Map<String, Object>> exceptionTableList = new ArrayList<>();

		for (int i = 0; i < exceptionTableLength; i++) {
			int startPc   = dis.readUnsignedShort();
			int endPc     = dis.readUnsignedShort();
			int handlerPc = dis.readUnsignedShort();
			int catchType = dis.readUnsignedShort();

			Map<String, Object> map = new LinkedHashMap<>();
			map.put("startPc", startPc);
			map.put("endPc", endPc);
			map.put("handlerPc", handlerPc);
			map.put("catchType", catchType);

			exceptionTableList.add(map);
		}

		exceptionTable.put("exceptionTableList", exceptionTableList);

		return exceptionTable;
	}

	/**
	 * 读取成员变量或者方法的公用属性
	 *
	 * @param poolMap
	 * @return 成员变量或方法属性信息
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readFieldOrMethod(Map<Integer, Map<String, Object>> poolMap) throws IOException {
		Map<String, Object> dataMap = new LinkedHashMap<>();

		// u2 access_flags;
		dataMap.put("access", dis.readUnsignedShort());

		// u2 name_index;
		dataMap.put("name", getConstantPoolValue(dis.readUnsignedShort(), "value", poolMap));

		// u2 descriptor_index;
		dataMap.put("desc", getConstantPoolValue(dis.readUnsignedShort(), "value", poolMap));

		// u2 attributes_count;
		int attributesCount = dis.readUnsignedShort();
		dataMap.put("attributesCount", attributesCount);

		// 读取成员变量属性信息
		dataMap.put("attributes", readAttributes(attributesCount, poolMap));

		return dataMap;
	}

	public static void main(String[] args) throws IOException {
		File classFile = new File("/Users/yz/Bytes.class");

		SimpleClassByteCodeParser codeParser  = new SimpleClassByteCodeParser();
		Map<String, Object>       byteCodeMap = codeParser.parseByteCode(new FileInputStream(classFile));
		System.out.println(JSON.toJSONString(byteCodeMap));
	}

}