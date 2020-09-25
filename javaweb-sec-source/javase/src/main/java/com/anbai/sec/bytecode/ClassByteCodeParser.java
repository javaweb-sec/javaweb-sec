package com.anbai.sec.bytecode;

import java.io.*;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.anbai.sec.bytecode.ClassByteCodeParser.Constant.*;
import static org.javaweb.utils.HexUtils.bytes2HexString;

public class ClassByteCodeParser {

	public enum Constant {
		CONSTANT_UTF8(1, "A UTF-8 encoded Unicode string"),
		CONSTANT_INTEGER(3, "An int literal value"),
		CONSTANT_FLOAT(4, "A float literal value"),
		CONSTANT_LONG(5, "A long literal value"),
		CONSTANT_DOUBLE(6, "A double literal value"),
		CONSTANT_CLASS(7, "A symbolic reference to a class or interface"),
		CONSTANT_STRING(8, "A String literal value"),
		CONSTANT_FIELD_REF(9, "A symbolic reference to a field"),
		CONSTANT_METHOD_REF(10, "A symbolic reference to a method declared in a class"),
		CONSTANT_INTERFACE_METHOD_REF(11, "A symbolic reference to a method declared in an interface"),
		CONSTANT_NAME_AND_TYPE(12, "Part of a symbolic reference to a field or method"),
		CONSTANT_METHOD_HANDLE(15, "represent a method handle"),
		CONSTANT_METHOD_TYPE(16, "represent a method type"),
		CONSTANT_DYNAMIC(17, "represent entities directly,"),
		CONSTANT_INVOKE_DYNAMIC(18, "represent entities directly,"),
		CONSTANT_MODULE(19, "represent a module"),
		CONSTANT_PACKAGE(20, "represent a package exported or opened by a module");

		private final int flag;

		private final String desc;

		Constant(int flag, String desc) {
			this.flag = flag;
			this.desc = desc;
		}

		public int getFlag() {
			return flag;
		}

		public String getDesc() {
			return desc;
		}
	}

	public static byte[] readBytes(InputStream in, int len) throws IOException {
		byte[] bytes = new byte[len];
		in.read(bytes);
		return bytes;
	}

	public static void main(String[] args) throws IOException {
		File            classFile = new File("/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javase/src/main/java/com/anbai/sec/classloader/TestHelloWorld.class");
		DataInputStream dis       = new DataInputStream(new FileInputStream(classFile));

		// u4 magic;
		String magic = bytes2HexString(readBytes(dis, 4));

		// 校验文件魔数
		if ("CAFEBABE".equals(magic)) {
			// u2 minor_version
			String minor = bytes2HexString(readBytes(dis, 2));

			// u2 major_version;
			String major = bytes2HexString(readBytes(dis, 2));

			// u2 constant_pool_count;
			int poolCount = dis.readUnsignedShort();

			Map<Integer, Map<String, Object>> constantPoolMap = new LinkedHashMap<>();

			// cp_info constant_pool[constant_pool_count-1];
			for (int i = 1; i <= poolCount - 1; i++) {
				int                 tag    = dis.readUnsignedByte();
				Map<String, Object> map    = new LinkedHashMap<>();
				int                 length = 0;

				if (tag == CONSTANT_UTF8.flag) {
//					CONSTANT_Utf8_info {
//						u1 tag;
//						u2 length;
//						u1 bytes[length];
//					}

					length = dis.readUnsignedShort();
					byte[] bytes = new byte[length];
					dis.read(bytes);

					map.put("tag", CONSTANT_UTF8);
					map.put("length", length);
					map.put("bytes", bytes);
				} else if (tag == CONSTANT_INTEGER.flag) {
//					CONSTANT_Integer_info {
//						u1 tag;
//						u4 bytes;
//					}

					int bytes = dis.readInt();

					map.put("tag", CONSTANT_INTEGER);
					map.put("bytes", bytes);
				} else if (tag == CONSTANT_FLOAT.flag) {
//					CONSTANT_Float_info {
//						u1 tag;
//						u4 bytes;
//					}

					int bytes = dis.readInt();

					map.put("tag", CONSTANT_FLOAT);
					map.put("bytes", bytes);
				} else if (tag == CONSTANT_LONG.flag) {
//					CONSTANT_Long_info {
//						u1 tag;
//						u4 high_bytes;
//						u4 low_bytes;
//					}

					int highBytes = dis.readInt();
					int lowBytes  = dis.readInt();

					map.put("tag", CONSTANT_LONG);
					map.put("highBytes", highBytes);
					map.put("lowBytes", lowBytes);
				} else if (tag == CONSTANT_DOUBLE.flag) {
//					CONSTANT_Double_info {
//						u1 tag;
//						u4 high_bytes;
//						u4 low_bytes;
//					}

					int highBytes = dis.readInt();
					int lowBytes  = dis.readInt();

					map.put("tag", CONSTANT_DOUBLE);
					map.put("highBytes", highBytes);
					map.put("lowBytes", lowBytes);
				} else if (tag == CONSTANT_CLASS.flag) {
//					CONSTANT_Class_info {
//						u1 tag;
//						u2 name_index;
//					}

					int nameIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_CLASS);
					map.put("nameIndex", nameIndex);
				} else if (tag == CONSTANT_STRING.flag) {
//					CONSTANT_String_info {
//						u1 tag;
//						u2 string_index;
//					}

					int stringIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_STRING);
					map.put("stringIndex", stringIndex);
				} else if (tag == CONSTANT_FIELD_REF.flag) {
//					CONSTANT_Fieldref_info {
//						u1 tag;
//						u2 class_index;
//						u2 name_and_type_index;
//					}

					int classIndex       = dis.readUnsignedShort();
					int nameAndTypeIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_FIELD_REF);
					map.put("classIndex", classIndex);
					map.put("nameAndTypeIndex", nameAndTypeIndex);
				} else if (tag == CONSTANT_METHOD_REF.flag) {
//					CONSTANT_Methodref_info {
//						u1 tag;
//						u2 class_index;
//						u2 name_and_type_index;
//					}

					int classIndex       = dis.readUnsignedShort();
					int nameAndTypeIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_METHOD_REF);
					map.put("classIndex", classIndex);
					map.put("nameAndTypeIndex", nameAndTypeIndex);
				} else if (tag == CONSTANT_INTERFACE_METHOD_REF.flag) {
//					CONSTANT_InterfaceMethodref_info {
//						u1 tag;
//						u2 class_index;
//						u2 name_and_type_index;
//					}

					int classIndex       = dis.readUnsignedShort();
					int nameAndTypeIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_INTERFACE_METHOD_REF);
					map.put("classIndex", classIndex);
					map.put("nameAndTypeIndex", nameAndTypeIndex);
				} else if (tag == CONSTANT_NAME_AND_TYPE.flag) {
//					CONSTANT_NameAndType_info {
//						u1 tag;
//						u2 name_index;
//						u2 descriptor_index;
//					}

					int nameIndex       = dis.readUnsignedShort();
					int descriptorIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_NAME_AND_TYPE);
					map.put("nameIndex", nameIndex);
					map.put("descriptorIndex", descriptorIndex);
				} else if (tag == CONSTANT_METHOD_HANDLE.flag) {
//					CONSTANT_MethodHandle_info {
//						u1 tag;
//						u1 reference_kind;
//						u2 reference_index;
//					}

					int referenceKind  = dis.readUnsignedByte();
					int referenceIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_METHOD_HANDLE);
					map.put("referenceKind", referenceKind);
					map.put("referenceIndex", referenceIndex);
				} else if (tag == CONSTANT_METHOD_TYPE.flag) {
//					CONSTANT_MethodType_info {
//						u1 tag;
//						u2 descriptor_index;
//					}

					int descriptorIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_METHOD_TYPE);
					map.put("descriptorIndex", descriptorIndex);
				} else if (tag == CONSTANT_DYNAMIC.flag) {
//					CONSTANT_Dynamic_info {
//						u1 tag;
//						u2 bootstrap_method_attr_index;
//						u2 name_and_type_index;
//					}

					int bootstrapMethodAttrIndex = dis.readUnsignedShort();
					int nameAndTypeIndex         = dis.readUnsignedShort();

					map.put("tag", CONSTANT_DYNAMIC);
					map.put("bootstrapMethodAttrIndex", bootstrapMethodAttrIndex);
					map.put("nameAndTypeIndex", nameAndTypeIndex);
				} else if (tag == CONSTANT_INVOKE_DYNAMIC.flag) {
//					CONSTANT_InvokeDynamic_info {
//						u1 tag;
//						u2 bootstrap_method_attr_index;
//						u2 name_and_type_index;
//					}

					int bootstrapMethodAttrIndex = dis.readUnsignedShort();
					int nameAndTypeIndex         = dis.readUnsignedShort();

					map.put("tag", CONSTANT_INVOKE_DYNAMIC);
					map.put("bootstrapMethodAttrIndex", bootstrapMethodAttrIndex);
					map.put("nameAndTypeIndex", nameAndTypeIndex);
				} else if (tag == CONSTANT_MODULE.flag) {
//					CONSTANT_Module_info {
//						u1 tag;
//						u2 name_index;
//					}

					int nameIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_MODULE);
					map.put("nameIndex", nameIndex);
				} else if (tag == CONSTANT_PACKAGE.flag) {
//					CONSTANT_Package_info {
//						u1 tag;
//						u2 name_index;
//					}

					int nameIndex = dis.readUnsignedShort();

					map.put("tag", CONSTANT_PACKAGE);
					map.put("nameIndex", nameIndex);
				}

				// Long和Double占两位
				if (tag == CONSTANT_LONG.flag || tag == CONSTANT_DOUBLE.flag) {
					i++;
				}

				constantPoolMap.put(i, map);
			}

//			for (Integer id : constantPoolMap.keySet()) {
//				Map<String, Object> map      = constantPoolMap.get(id);
//				Constant            constant = (Constant) map.get("tag");
//
//				if (constant == CONSTANT_UTF8) {
//					System.out.println(new String((byte[]) map.get("bytes")));
//				}
//			}

			// u2 access_flags;
			int accessFlags = dis.readUnsignedShort();

			// u2 this_class;
			int thisClass = dis.readUnsignedShort();

			// u2 super_class;
			int superClass = dis.readUnsignedShort();

			// u2 interfaces_count;
			int interfacesCount = dis.readUnsignedShort();

			// u2 interfaces[interfaces_count];
			for (int i = 0; i < interfacesCount; i++) {
				int index = dis.readUnsignedShort();
			}

			// u2 fields_count;
			int fieldsCount = dis.readUnsignedShort();

			// field_info fields[fields_count];
			for (int i = 0; i < fieldsCount; i++) {
//				field_info {
//					u2 access_flags;
//					u2 name_index;
//					u2 descriptor_index;
//					u2 attributes_count;
//					attribute_info attributes[attributes_count];
//				}

				int fieldAccessFlags     = dis.readUnsignedShort();
				int fieldNameIndex       = dis.readUnsignedShort();
				int fieldDescriptorIndex = dis.readUnsignedShort();
				int fieldAttributesCount = dis.readUnsignedShort();

//				attribute_info {
//					u2 attribute_name_index;
//					u4 attribute_length;
//					u1 info[attribute_length];
//				}
			}
		} else {
			throw new RuntimeException("Class文件格式错误!");
		}
	}

}
