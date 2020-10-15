package com.anbai.sec.bytecode;

import com.alibaba.fastjson.JSON;

import java.io.*;
import java.util.*;

import static com.anbai.sec.bytecode.ClassByteCodeParser.Constant.*;
import static com.anbai.sec.bytecode.ClassByteCodeParser.Opcodes.WIDE;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Java类字节码解析，参考：https://docs.oracle.com/javase/specs/jvms/se15/jvms15.pdf和https://github.com/ingokegel/jclasslib
 */
public class ClassByteCodeParser {

	/**
	 * 转换为数据输入流
	 */
	private DataInputStream dis;

	/**
	 * Class文件魔数
	 */
	private int magic;

	/**
	 * Class小版本号
	 */
	private int minor;

	/**
	 * Class大版本号
	 */
	private int major;

	/**
	 * 常量池中的对象数量
	 */
	private int poolCount;

	/**
	 * 创建常量池Map
	 */
	private final Map<Integer, Map<String, Object>> constantPoolMap = new LinkedHashMap<>();

	/**
	 * 类访问修饰符
	 */
	private int accessFlags;

	/**
	 * thisClass
	 */
	private String thisClass;

	/**
	 * superClass
	 */
	private String superClass;

	/**
	 * 接口数
	 */
	private int interfacesCount;

	/**
	 * 接口Index数组
	 */
	private String[] interfaces;

	/**
	 * 成员变量数量
	 */
	private int fieldsCount;

	/**
	 * 成员变量数组
	 */
	private final Set<Map<String, Object>> fieldList = new HashSet<>();

	/**
	 * 方法数
	 */
	private int methodsCount;

	/**
	 * 方法数组
	 */
	private final Set<Map<String, Object>> methodList = new HashSet<>();

	/**
	 * 属性数
	 */
	private int attributesCount;

	/**
	 * 属性
	 */
	private Map<String, Object> attributes;

	/**
	 * 枚举常量池类型，兼容到JDK15。
	 * Constant Kind                Tag  Section
	 * CONSTANT_Class                7   §4.4.1
	 * CONSTANT_Fieldref             9   §4.4.2
	 * CONSTANT_Methodref            10  §4.4.2
	 * CONSTANT_InterfaceMethodref   11  §4.4.2
	 * CONSTANT_String               8   §4.4.3
	 * CONSTANT_Integer              3   §4.4.4
	 * CONSTANT_Float                4   §4.4.4
	 * CONSTANT_Long                 5   §4.4.5
	 * CONSTANT_Double               6   §4.4.5
	 * CONSTANT_NameAndType          12  §4.4.6
	 * CONSTANT_Utf8                 1   §4.4.7
	 * CONSTANT_MethodHandle         15  §4.4.8
	 * CONSTANT_MethodType           16  §4.4.9
	 * CONSTANT_Dynamic              17  §4.4.10
	 * CONSTANT_InvokeDynamic        18  §4.4.10
	 * CONSTANT_Module               19  §4.4.11
	 * CONSTANT_Package              20  §4.4.12
	 */
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

		public static Constant getConstant(int tag) {
			Constant[] constants = Constant.values();

			for (Constant constant : constants) {
				if (constant.flag == tag) {
					return constant;
				}
			}

			return null;
		}

	}

	/**
	 * 指令集 §6.5 Instructions
	 */
	public enum Opcodes {
		NOP(0, "nop"),
		ACONST_NULL(1, "aconst_null"),
		ICONST_M1(2, "iconst_m1"),
		ICONST_0(3, "iconst_0"),
		ICONST_1(4, "iconst_1"),
		ICONST_2(5, "iconst_2"),
		ICONST_3(6, "iconst_3"),
		ICONST_4(7, "iconst_4"),
		ICONST_5(8, "iconst_5"),
		LCONST_0(9, "lconst_0"),
		LCONST_1(10, "lconst_1"),
		FCONST_0(11, "fconst_0"),
		FCONST_1(12, "fconst_1"),
		FCONST_2(13, "fconst_2"),
		DCONST_0(14, "dconst_0"),
		DCONST_1(15, "dconst_1"),
		BIPUSH(16, "bipush"),
		SIPUSH(17, "sipush"),
		LDC(18, "ldc"),
		LDC_W(19, "ldc_w"),
		LDC2_W(20, "ldc2_w"),
		ILOAD(21, "iload"),
		LLOAD(22, "lload"),
		FLOAD(23, "fload"),
		DLOAD(24, "dload"),
		ALOAD(25, "aload"),
		ILOAD_0(26, "iload_0"),
		ILOAD_1(27, "iload_1"),
		ILOAD_2(28, "iload_2"),
		ILOAD_3(29, "iload_3"),
		LLOAD_0(30, "lload_0"),
		LLOAD_1(31, "lload_1"),
		LLOAD_2(32, "lload_2"),
		LLOAD_3(33, "lload_3"),
		FLOAD_0(34, "fload_0"),
		FLOAD_1(35, "fload_1"),
		FLOAD_2(36, "fload_2"),
		FLOAD_3(37, "fload_3"),
		DLOAD_0(38, "dload_0"),
		DLOAD_1(39, "dload_1"),
		DLOAD_2(40, "dload_2"),
		DLOAD_3(41, "dload_3"),
		ALOAD_0(42, "aload_0"),
		ALOAD_1(43, "aload_1"),
		ALOAD_2(44, "aload_2"),
		ALOAD_3(45, "aload_3"),
		IALOAD(46, "iaload"),
		LALOAD(47, "laload"),
		FALOAD(48, "faload"),
		DALOAD(49, "daload"),
		AALOAD(50, "aaload"),
		BALOAD(51, "baload"),
		CALOAD(52, "caload"),
		SALOAD(53, "saload"),
		ISTORE(54, "istore"),
		LSTORE(55, "lstore"),
		FSTORE(56, "fstore"),
		DSTORE(57, "dstore"),
		ASTORE(58, "astore"),
		ISTORE_0(59, "istore_0"),
		ISTORE_1(60, "istore_1"),
		ISTORE_2(61, "istore_2"),
		ISTORE_3(62, "istore_3"),
		LSTORE_0(63, "lstore_0"),
		LSTORE_1(64, "lstore_1"),
		LSTORE_2(65, "lstore_2"),
		LSTORE_3(66, "lstore_3"),
		FSTORE_0(67, "fstore_0"),
		FSTORE_1(68, "fstore_1"),
		FSTORE_2(69, "fstore_2"),
		FSTORE_3(70, "fstore_3"),
		DSTORE_0(71, "dstore_0"),
		DSTORE_1(72, "dstore_1"),
		DSTORE_2(73, "dstore_2"),
		DSTORE_3(74, "dstore_3"),
		ASTORE_0(75, "astore_0"),
		ASTORE_1(76, "astore_1"),
		ASTORE_2(77, "astore_2"),
		ASTORE_3(78, "astore_3"),
		IASTORE(79, "iastore"),
		LASTORE(80, "lastore"),
		FASTORE(81, "fastore"),
		DASTORE(82, "dastore"),
		AASTORE(83, "aastore"),
		BASTORE(84, "bastore"),
		CASTORE(85, "castore"),
		SASTORE(86, "sastore"),
		POP(87, "pop"),
		POP2(88, "pop2"),
		DUP(89, "dup"),
		DUP_X1(90, "dup_x1"),
		DUP_X2(91, "dup_x2"),
		DUP2(92, "dup2"),
		DUP2_X1(93, "dup2_x1"),
		DUP2_X2(94, "dup2_x2"),
		SWAP(95, "swap"),
		IADD(96, "iadd"),
		LADD(97, "ladd"),
		FADD(98, "fadd"),
		DADD(99, "dadd"),
		ISUB(100, "isub"),
		LSUB(101, "lsub"),
		FSUB(102, "fsub"),
		DSUB(103, "dsub"),
		IMUL(104, "imul"),
		LMUL(105, "lmul"),
		FMUL(106, "fmul"),
		DMUL(107, "dmul"),
		IDIV(108, "idiv"),
		LDIV(109, "ldiv"),
		FDIV(110, "fdiv"),
		DDIV(111, "ddiv"),
		IREM(112, "irem"),
		LREM(113, "lrem"),
		FREM(114, "frem"),
		DREM(115, "drem"),
		INEG(116, "ineg"),
		LNEG(117, "lneg"),
		FNEG(118, "fneg"),
		DNEG(119, "dneg"),
		ISHL(120, "ishl"),
		LSHL(121, "lshl"),
		ISHR(122, "ishr"),
		LSHR(123, "lshr"),
		IUSHR(124, "iushr"),
		LUSHR(125, "lushr"),
		IAND(126, "iand"),
		LAND(127, "land"),
		IOR(128, "ior"),
		LOR(129, "lor"),
		IXOR(130, "ixor"),
		LXOR(131, "lxor"),
		IINC(132, "iinc"),
		I2L(133, "i2l"),
		I2F(134, "i2f"),
		I2D(135, "i2d"),
		L2I(136, "l2i"),
		L2F(137, "l2f"),
		L2D(138, "l2d"),
		F2I(139, "f2i"),
		F2L(140, "f2l"),
		F2D(141, "f2d"),
		D2I(142, "d2i"),
		D2L(143, "d2l"),
		D2F(144, "d2f"),
		I2B(145, "i2b"),
		I2C(146, "i2c"),
		I2S(147, "i2s"),
		LCMP(148, "lcmp"),
		FCMPL(149, "fcmpl"),
		FCMPG(150, "fcmpg"),
		DCMPL(151, "dcmpl"),
		DCMPG(152, "dcmpg"),
		IFEQ(153, "ifeq"),
		IFNE(154, "ifne"),
		IFLT(155, "iflt"),
		IFGE(156, "ifge"),
		IFGT(157, "ifgt"),
		IFLE(158, "ifle"),
		IF_ICMPEQ(159, "if_icmpeq"),
		IF_ICMPNE(160, "if_icmpne"),
		IF_ICMPLT(161, "if_icmplt"),
		IF_ICMPGE(162, "if_icmpge"),
		IF_ICMPGT(163, "if_icmpgt"),
		IF_ICMPLE(164, "if_icmple"),
		IF_ACMPEQ(165, "if_acmpeq"),
		IF_ACMPNE(166, "if_acmpne"),
		GOTO(167, "goto"),
		JSR(168, "jsr"),
		RET(169, "ret"),
		TABLESWITCH(170, "tableswitch"),
		LOOKUPSWITCH(171, "lookupswitch"),
		IRETURN(172, "ireturn"),
		LRETURN(173, "lreturn"),
		FRETURN(174, "freturn"),
		DRETURN(175, "dreturn"),
		ARETURN(176, "areturn"),
		RETURN(177, "return"),
		GETSTATIC(178, "getstatic"),
		PUTSTATIC(179, "putstatic"),
		GETFIELD(180, "getfield"),
		PUTFIELD(181, "putfield"),
		INVOKEVIRTUAL(182, "invokevirtual"),
		INVOKESPECIAL(183, "invokespecial"),
		INVOKESTATIC(184, "invokestatic"),
		INVOKEINTERFACE(185, "invokeinterface"),
		INVOKEDYNAMIC(186, "invokedynamic"),
		NEW(187, "new"),
		NEWARRAY(188, "newarray"),
		ANEWARRAY(189, "anewarray"),
		ARRAYLENGTH(190, "arraylength"),
		ATHROW(191, "athrow"),
		CHECKCAST(192, "checkcast"),
		INSTANCEOF(193, "instanceof"),
		MONITORENTER(194, "monitorenter"),
		MONITOREXIT(195, "monitorexit"),
		WIDE(196, "wide"),
		MULTIANEWARRAY(197, "multianewarray"),
		IFNULL(198, "ifnull"),
		IFNONNULL(199, "ifnonnull"),
		GOTO_W(200, "goto_w"),
		JSR_W(201, "jsr_w"),
		BREAKPOINT(202, "breakpoint"),
		IMPDEP1(254, "impdep1"),
		IMPDEP(255, "impdep");

		private final int opCode;

		private final String desc;

		Opcodes(int opCode, String desc) {
			this.opCode = opCode;
			this.desc = desc;
		}

		public int getOpCode() {
			return opCode;
		}

		public String getDesc() {
			return desc;
		}

		public static Opcodes getOpcodes(int opCode) {
			Opcodes[] opcodes = Opcodes.values();

			for (Opcodes code : opcodes) {
				if (code.opCode == opCode) {
					return code;
				}
			}

			return null;
		}

	}

	/**
	 * 解析Class字节码
	 *
	 * @param in 类字节码输入流
	 * @throws IOException 解析IO异常
	 */
	private void parseByteCode(InputStream in) throws IOException {
		this.dis = new DataInputStream(in);

		// u4 magic;
		int magic = dis.readInt();

		// 校验文件魔数
		if (0xCAFEBABE == magic) {
			this.magic = magic;

			// u2 minor_version
			this.minor = dis.readUnsignedShort();

			// u2 major_version;
			this.major = dis.readUnsignedShort();

			// 解析常量池数据
			parseConstantPool();

			// u2 access_flags;
			this.accessFlags = dis.readUnsignedShort();

			// u2 this_class;
			this.thisClass = (String) getConstantPoolValue(dis.readUnsignedShort());

			// u2 super_class;
			int superClassIndex = dis.readUnsignedShort();

			// 当解析Object类的时候super_class为0
			if (superClassIndex != 0) {
				this.superClass = (String) getConstantPoolValue(superClassIndex);
			} else {
				this.superClass = "java/lang/Object";
			}

			// u2 interfaces_count;
			this.interfacesCount = dis.readUnsignedShort();

			// 创建接口Index数组
			this.interfaces = new String[interfacesCount];

			// u2 interfaces[interfaces_count];
			for (int i = 0; i < interfacesCount; i++) {
				int index = dis.readUnsignedShort();

				// 设置接口名称
				this.interfaces[i] = (String) getConstantPoolValue(index);
			}

			// u2 fields_count;
			this.fieldsCount = dis.readUnsignedShort();

			// field_info fields[fields_count];
			for (int i = 0; i < this.fieldsCount; i++) {
//              field_info {
//                  u2 access_flags;
//                  u2 name_index;
//                  u2 descriptor_index;
//                  u2 attributes_count;
//                  attribute_info attributes[attributes_count];
//              }

				this.fieldList.add(readFieldOrMethod());
			}

			// u2 methods_count;
			this.methodsCount = dis.readUnsignedShort();

			// method_info methods[methods_count];
			for (int i = 0; i < this.methodsCount; i++) {
//              method_info {
//                  u2 access_flags;
//                  u2 name_index;
//                  u2 descriptor_index;
//                  u2 attributes_count;
//                  attribute_info attributes[attributes_count];
//              }

				methodList.add(readFieldOrMethod());
			}

			// u2 attributes_count;
			this.attributesCount = dis.readUnsignedShort();

			// attribute_info attributes[attributes_count];
			this.attributes = readAttributes(attributesCount);
		} else {
			throw new RuntimeException("Class文件格式错误!");
		}
	}

	/**
	 * 读取成员变量或者方法的公用属性
	 *
	 * @return 成员变量或方法属性信息
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readFieldOrMethod() throws IOException {
		Map<String, Object> dataMap = new LinkedHashMap<>();

		// u2 access_flags;
		dataMap.put("access", dis.readUnsignedShort());

		// u2 name_index;
		dataMap.put("name", getConstantPoolValue(dis.readUnsignedShort()));

		// u2 descriptor_index;
		dataMap.put("desc", getConstantPoolValue(dis.readUnsignedShort()));

		// u2 attributes_count;
		int attributesCount = dis.readUnsignedShort();
		dataMap.put("attributesCount", attributesCount);

		// 读取成员变量属性信息
		dataMap.put("attributes", readAttributes(attributesCount));

		return dataMap;
	}

	/**
	 * 通过常量池中的索引ID和名称获取常量池中的值
	 *
	 * @param index 索引ID
	 * @return 常量池对象值
	 */
	private Object getConstantPoolValue(int index) {
		if (constantPoolMap.containsKey(index)) {
			Map<String, Object> dataMap  = constantPoolMap.get(index);
			Constant            constant = (Constant) dataMap.get("tag");

			switch (constant) {
				case CONSTANT_UTF8:
				case CONSTANT_INTEGER:
				case CONSTANT_FLOAT:
				case CONSTANT_LONG:
				case CONSTANT_DOUBLE:
					return dataMap.get("value");
				case CONSTANT_CLASS:
				case CONSTANT_MODULE:
				case CONSTANT_PACKAGE:
					return dataMap.get("nameValue");
				case CONSTANT_STRING:
					return dataMap.get("stringValue");
				case CONSTANT_FIELD_REF:
				case CONSTANT_METHOD_REF:
				case CONSTANT_INTERFACE_METHOD_REF:
					return dataMap.get("classValue") + "." + dataMap.get("nameAndTypeValue");
				case CONSTANT_NAME_AND_TYPE:
				case CONSTANT_METHOD_TYPE:
					return dataMap.get("descriptorValue");
				case CONSTANT_METHOD_HANDLE:
					return dataMap.get("referenceValue");
				case CONSTANT_DYNAMIC:
				case CONSTANT_INVOKE_DYNAMIC:
					return dataMap.get("bootstrapMethodAttrValue") + "." + dataMap.get("nameAndTypeValue");
				default:
					break;
			}
		}

		return null;
	}

	/**
	 * 解析Attributes
	 *
	 * @param attrCount Attributes数量
	 * @throws IOException 读取数据IO异常
	 */
	private Map<String, Object> readAttributes(int attrCount) throws IOException {
		Map<String, Object> attributeMap = new LinkedHashMap<>();

		// attribute_info attributes[attributes_count];
		for (int j = 0; j < attrCount; j++) {
//          attribute_info {
//              u2 attribute_name_index;
//              u4 attribute_length;
//              u1 info[attribute_length];
//          }

			// u2 attribute_name_index;
			String attributeName = (String) getConstantPoolValue(dis.readUnsignedShort());
			attributeMap.put("attributeName", attributeName);

			// u4 attribute_length;
			int attributeLength = dis.readInt();
			attributeMap.put("attributeLength", attributeLength);

			// u1 info[attribute_length];
			if ("ConstantValue".equals(attributeName)) {
//              ConstantValue_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 constantvalue_index;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 constantvalue_index;
				attrMap.put("constantValue", getConstantPoolValue(dis.readUnsignedShort()));

				attributeMap.put("ConstantValue", attrMap);
			} else if ("Code".equals(attributeName)) {
//              Code_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 max_stack;
//                  u2 max_locals;
//                  u4 code_length;
//                  u1 code[code_length];
//                  u2 exception_table_length;
//                  { u2 start_pc;
//                      u2 end_pc;
//                      u2 handler_pc;
//                      u2 catch_type;
//                  } exception_table[exception_table_length];
//                  u2 attributes_count;
//                  attribute_info attributes[attributes_count];
//              }

				int          maxStack   = dis.readUnsignedShort();
				int          maxLocals  = dis.readUnsignedShort();
				int          codeLength = dis.readInt();
				List<String> opcodeList = new ArrayList<>();
				byte[]       bytes      = new byte[codeLength];

				// 读取所有的code字节
				dis.read(bytes);

				// 创建Code输入流
				DataInputStream bis = new DataInputStream(new ByteArrayInputStream(bytes));

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("maxStack", maxStack);
				attrMap.put("maxLocals", maxLocals);
				attrMap.put("codeLength", codeLength);

				// 是否是宽类型
				boolean wide = false;

				for (int offset = 0; offset < codeLength; offset++) {
					int     branchOffset          = -1;
					int     defaultOffset         = -1;
					int     switchNumberofPairs   = -1;
					int     switchNumberOfOffsets = -1;
					int     immediateByte         = -1;
					int     immediateShort        = -1;
					int     arrayDimensions       = 0;
					int     incrementConst        = -1;
					int     incrementConst2       = -1;
					int     switchMatch           = -1;
					int     switchOffset          = -1;
					int[]   switchJumpOffsets     = null;
					int     bytesToRead           = 0;
					int     code                  = bis.readUnsignedByte();
					Opcodes opcode                = Opcodes.getOpcodes(code);

					if (opcode == null) {
						continue;
					}

					switch (opcode) {
						case BIPUSH:
						case LDC:
						case ILOAD:
						case LLOAD:
						case FLOAD:
						case DLOAD:
						case ALOAD:
						case ISTORE:
						case LSTORE:
						case FSTORE:
						case DSTORE:
						case ASTORE:
						case RET:
						case NEWARRAY:
							if (wide) {
								immediateByte = bis.readUnsignedShort();
							} else {
								immediateByte = bis.readUnsignedByte();
							}

							addOpcodes(opcodeList, opcode, immediateByte);

							// 因为读取了byte，所以需要重新计算bis偏移量
							offset += wide ? 2 : 1;
							break;
						case LDC_W:
						case LDC2_W:
						case GETSTATIC:
						case PUTSTATIC:
						case GETFIELD:
						case PUTFIELD:
						case INVOKEVIRTUAL:
						case INVOKESPECIAL:
						case INVOKESTATIC:
						case NEW:
						case ANEWARRAY:
						case CHECKCAST:
						case INSTANCEOF:
						case SIPUSH:
							addOpcodes(opcodeList, opcode, bis.readUnsignedShort());

							offset += 2;
							break;
						case IFEQ:
						case IFNE:
						case IFLT:
						case IFGE:
						case IFGT:
						case IFLE:
						case IF_ICMPEQ:
						case IF_ICMPNE:
						case IF_ICMPLT:
						case IF_ICMPGE:
						case IF_ICMPGT:
						case IF_ICMPLE:
						case IF_ACMPEQ:
						case IF_ACMPNE:
						case GOTO:
						case JSR:
						case IFNULL:
						case IFNONNULL:
							branchOffset = bis.readShort();

							opcodeList.add(opcode.getDesc() + " " + branchOffset);

							offset += 2;
							break;
						case GOTO_W:
						case JSR_W:
							branchOffset = bis.readInt();

							opcodeList.add(opcode.getDesc() + " " + branchOffset);

							offset += 4;
							break;
						case IINC:
							if (wide) {
								incrementConst = bis.readUnsignedShort();
							} else {
								incrementConst = bis.readUnsignedByte();
							}

							if (wide) {
								incrementConst2 = bis.readUnsignedShort();
							} else {
								incrementConst2 = bis.readUnsignedByte();
							}

							opcodeList.add(opcode.getDesc() + " " + incrementConst + " by " + incrementConst2);

							offset += wide ? 4 : 2;
							break;
						case TABLESWITCH:
							bytesToRead = readPaddingBytes(bytes, bis);

							defaultOffset = bis.readInt();
							int lowByte = bis.readInt();
							int highByte = bis.readInt();

							switchNumberOfOffsets = highByte - lowByte + 1;
							switchJumpOffsets = new int[switchNumberOfOffsets];

							for (int k = 0; k < switchNumberOfOffsets; k++) {
								switchJumpOffsets[k] = bis.readInt();
							}

							opcodeList.add(opcode.getDesc());

							offset += bytesToRead + 12 + 4 * switchNumberOfOffsets;
							break;
						case LOOKUPSWITCH:
							bytesToRead = readPaddingBytes(bytes, bis);

							defaultOffset = bis.readInt();
							switchNumberofPairs = bis.readInt();

							for (int k = 0; k < switchNumberofPairs; k++) {
								switchMatch = bis.readInt();
								switchOffset = bis.readInt();
							}

							opcodeList.add(opcode.getDesc());

							offset += bytesToRead + 8 + 8 * switchNumberofPairs;
							break;
						case INVOKEINTERFACE:
							immediateShort = bis.readUnsignedShort();
							offset += 2;

							int count = bis.readUnsignedByte();

							// 下1个byte永远为0，所以直接丢弃
							bis.readByte();

							addOpcodes(opcodeList, opcode, immediateShort);

							offset += 2;
							break;
						case INVOKEDYNAMIC:
							immediateShort = bis.readUnsignedShort();
							offset += 2;

							// 下2个byte永远为0，所以直接丢弃
							bis.readUnsignedShort();

							addOpcodes(opcodeList, opcode, immediateShort);

							offset += 2;
							break;
						case MULTIANEWARRAY:
							immediateShort = bis.readUnsignedShort();
							offset += 2;

							arrayDimensions = bis.readUnsignedByte();

							addOpcodes(opcodeList, opcode, immediateShort);

							offset += 1;
							break;
						default:
							opcodeList.add(opcode.getDesc());
					}

					wide = (WIDE == opcode);
				}

				attrMap.put("opcodes", opcodeList);

				// 读取异常表
				attrMap.put("exceptionTable", readExceptionTable());

				// u2 attributes_count;
				int attributesCount = dis.readShort();
				attrMap.put("attributeLength", attributeLength);
				attrMap.put("attributes", readAttributes(attributesCount));

				// 递归读取属性信息
				attributeMap.put("Code", attrMap);
			} else if ("StackMapTable".equals(attributeName)) {
//              StackMapTable_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 number_of_entries;
//                  stack_map_frame entries[number_of_entries];
//              }

				int numberOfEntries = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object>       attrMap   = new LinkedHashMap<>();
				List<Map<String, Object>> entryList = new ArrayList<>();
				attrMap.put("numberOfEntries", numberOfEntries);

				for (int i = 0; i < numberOfEntries; i++) {
					int                 frameType = dis.readUnsignedByte();
					Map<String, Object> entryMap  = new LinkedHashMap<>();
					entryMap.put("frameType", frameType);

//                  union stack_map_frame {
//                      same_frame;
//                      same_locals_1_stack_item_frame;
//                      same_locals_1_stack_item_frame_extended;
//                      chop_frame;
//                      same_frame_extended;
//                      append_frame;
//                      full_frame;
//                  }

					if (frameType >= 0 && frameType <= 63) {
						// same_frame 0-63

//                      same_frame {
//                          u1 frame_type = SAME; /* 0-63 */
//                      }
					} else if (frameType >= 64 && frameType <= 127) {
						// same_locals_1_stack_item_frame 64-127

//                      same_locals_1_stack_item_frame {
//                          u1 frame_type = SAME_LOCALS_1_STACK_ITEM; /* 64-127 */
//                          verification_type_info stack[1];
//                      }

						attrMap.put("typeInfoMap", readVerificationTypeInfo());
					} else if (frameType == 247) {
						// same_locals_1_stack_item_frame_extended 247

//                      same_locals_1_stack_item_frame_extended {
//                          u1 frame_type = SAME_LOCALS_1_STACK_ITEM_EXTENDED; /* 247 */
//                          u2 offset_delta;
//                          verification_type_info stack[1];
//                      }

						int offsetDelta = dis.readUnsignedShort();

						attrMap.put("offsetDelta", offsetDelta);
						attrMap.put("typeInfoMap", readVerificationTypeInfo());
					} else if (frameType >= 248 && frameType <= 250) {
						//  chop_frame 248-250

//                      chop_frame {
//                          u1 frame_type = CHOP; /* 248-250 */
//                          u2 offset_delta;
//                      }

						int offsetDelta = dis.readUnsignedShort();
						attrMap.put("offsetDelta", offsetDelta);
					} else if (frameType == 251) {
						// same_frame_extended 251

//                      same_frame_extended {
//                          u1 frame_type = SAME_FRAME_EXTENDED; /* 251 */
//                          u2 offset_delta;
//                      }

						int offsetDelta = dis.readUnsignedShort();
						attrMap.put("offsetDelta", offsetDelta);
					} else if (frameType >= 252 && frameType <= 254) {
						// append_frame 252-254

//                      append_frame {
//                          u1 frame_type = APPEND; /* 252-254 */
//                          u2 offset_delta;
//                          verification_type_info locals[frame_type - 251];
//                      }

						int offsetDelta = dis.readUnsignedShort();
						attrMap.put("offsetDelta", offsetDelta);

						List<Map<String, Object>> typeInfoList = new ArrayList<>();

						for (int k = 0; k < frameType - 251; k++) {
							typeInfoList.add(readVerificationTypeInfo());
						}

						attrMap.put("typeInfoList", typeInfoList);
					} else {
						// full_frame 255

//                      full_frame {
//                          u1 frame_type = FULL_FRAME; /* 255 */
//                          u2 offset_delta;
//                          u2 number_of_locals;
//                          verification_type_info locals[number_of_locals];
//                          u2 number_of_stack_items;
//                          verification_type_info stack[number_of_stack_items];
//                      }

						// u2 offset_delta;
						attrMap.put("offsetDelta", dis.readUnsignedShort());

						// u2 number_of_locals;
						int numberOfLocals = dis.readUnsignedShort();
						attrMap.put("numberOfLocals", numberOfLocals);

						List<Map<String, Object>> localsTypeInfoList = new ArrayList<>();

						// verification_type_info locals[number_of_locals];
						for (int k = 0; k < numberOfLocals; k++) {
							localsTypeInfoList.add(readVerificationTypeInfo());
						}

						attrMap.put("localsTypeInfoList", localsTypeInfoList);

						// u2 number_of_stack_items;
						int numberOfStackItems = dis.readUnsignedShort();
						attrMap.put("numberOfStackItems", numberOfStackItems);

						List<Map<String, Object>> stackTypeInfoList = new ArrayList<>();

						// verification_type_info stack[number_of_stack_items];
						for (int k = 0; k < numberOfStackItems; k++) {
							stackTypeInfoList.add(readVerificationTypeInfo());
						}

						attrMap.put("stackTypeInfoList", stackTypeInfoList);
					}

					entryList.add(entryMap);
				}

				attrMap.put("entryList", entryList);
				attributeMap.put("StackMapTable", attrMap);
			} else if ("Exceptions".equals(attributeName)) {
//              Exceptions_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 number_of_exceptions;
//                  u2 exception_index_table[number_of_exceptions];
//              }

				int numberOfExceptions = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("numberOfExceptions", numberOfExceptions);

				List<Object> exceptionList = new ArrayList<>();

				for (int i = 0; i < numberOfExceptions; i++) {
					exceptionList.add(getConstantPoolValue(dis.readUnsignedShort()));
				}

				attrMap.put("exceptionList", exceptionList);
				attributeMap.put("Exceptions", attrMap);
			} else if ("InnerClasses".equals(attributeName)) {
//              InnerClasses_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 number_of_classes;
//                  { u2 inner_class_info_index;
//                      u2 outer_class_info_index;
//                      u2 inner_name_index;
//                      u2 inner_class_access_flags;
//                  } classes[number_of_classes];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("exceptionTable", readExceptionTable());
				attributeMap.put("InnerClasses", attrMap);
			} else if ("EnclosingMethod".equals(attributeName)) {
//              EnclosingMethod_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 class_index;
//                  u2 method_index;
//              }

				// u2 class_index;
				int classIndex = dis.readUnsignedShort();

				// u2 method_index;
				int methodIndex = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				attrMap.put("classIndex", classIndex);
				attrMap.put("methodIndex", methodIndex);

				attributeMap.put("EnclosingMethod", attrMap);
			} else if ("Synthetic".equals(attributeName)) {
//              Synthetic_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attributeMap.put("Synthetic", attrMap);
			} else if ("Signature".equals(attributeName)) {
//              Signature_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 signature_index;
//              }

				int signatureIndex = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("signatureIndex", signatureIndex);
				attributeMap.put("Signature", attrMap);
			} else if ("SourceFile".equals(attributeName)) {
//              SourceFile_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 sourcefile_index;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 sourcefile_index;
				attrMap.put("sourceFile", getConstantPoolValue(dis.readUnsignedShort()));
				attributeMap.put("SourceFile", attrMap);
			} else if ("SourceDebugExtension".equals(attributeName)) {
//              SourceDebugExtension_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u1 debug_extension[attribute_length];
//              }

				byte[] bytes = new byte[attributeLength];

				dis.read(bytes);

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("bytes", bytes);
				attributeMap.put("SourceDebugExtension", attrMap);
			} else if ("LineNumberTable".equals(attributeName)) {
//              LineNumberTable_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 line_number_table_length;
//                  { u2 start_pc;
//                      u2 line_number;
//                  } line_number_table[line_number_table_length];
//              }

				int lineNumberTableLength = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("lineNumberTableLength", lineNumberTableLength);

				List<Map<String, Object>> lineNumberTableList = new ArrayList<>();

				for (int i = 0; i < lineNumberTableLength; i++) {
					int startPc    = dis.readUnsignedShort();
					int lineNumber = dis.readUnsignedShort();

					Map<String, Object> lineNumberTableMap = new LinkedHashMap<>();
					lineNumberTableMap.put("startPc", startPc);
					lineNumberTableMap.put("lineNumber", lineNumber);

					lineNumberTableList.add(lineNumberTableMap);
				}

				attrMap.put("lineNumberTableList", lineNumberTableList);
				attributeMap.put("LineNumberTable", attrMap);
			} else if ("LocalVariableTable".equals(attributeName)) {
//              LocalVariableTable_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 local_variable_table_length;
//                  { u2 start_pc;
//                      u2 length;
//                      u2 name_index;
//                      u2 descriptor_index;
//                      u2 index;
//                  } local_variable_table[local_variable_table_length];
//              }

				int localVariableTableLength = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("localVariableTableLength", localVariableTableLength);

				List<Map<String, Object>> localVariableTableList = new ArrayList<>();

				// local_variable_table[local_variable_table_length];
				for (int i = 0; i < localVariableTableLength; i++) {
					Map<String, Object> localVariableTableMap = new LinkedHashMap<>();

					// u2 start_pc;
					localVariableTableMap.put("startPc", dis.readUnsignedShort());

					// u2 length;
					localVariableTableMap.put("length", dis.readUnsignedShort());

					// u2 name_index; 参数名称
					localVariableTableMap.put("name", getConstantPoolValue(dis.readUnsignedShort()));

					// u2 descriptor_index; 参数描述符
					localVariableTableMap.put("desc", getConstantPoolValue(dis.readUnsignedShort()));

					// u2 index;
					localVariableTableMap.put("index", dis.readUnsignedShort());

					localVariableTableList.add(localVariableTableMap);
				}

				attrMap.put("localVariableTableList", localVariableTableList);
				attributeMap.put("LocalVariableTable", attrMap);
			} else if ("LocalVariableTypeTable".equals(attributeName)) {
//              LocalVariableTypeTable_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 local_variable_type_table_length;
//                  { u2 start_pc;
//                      u2 length;
//                      u2 name_index;
//                      u2 signature_index;
//                      u2 index;
//                  } local_variable_type_table[local_variable_type_table_length];
//              }

				int localVariableTypeTableLength = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("localVariableTypeTableLength", localVariableTypeTableLength);

				List<Map<String, Object>> localVariableTypeTableList = new ArrayList<>();

				// local_variable_type_table[local_variable_type_table_length];
				for (int i = 0; i < localVariableTypeTableLength; i++) {
					Map<String, Object> localVariableTypeMap = new LinkedHashMap<>();

					// u2 start_pc;
					localVariableTypeMap.put("startPc", dis.readUnsignedShort());

					// u2 length;
					localVariableTypeMap.put("length", dis.readUnsignedShort());

					// u2 name_index;
					localVariableTypeMap.put("nameIndex", dis.readUnsignedShort());

					// u2 signature_index;
					localVariableTypeMap.put("signatureIndex", dis.readUnsignedShort());

					// u2 index;
					localVariableTypeMap.put("index", dis.readUnsignedShort());

					localVariableTypeTableList.add(localVariableTypeMap);
				}

				attrMap.put("localVariableTypeTableList", localVariableTypeTableList);
				attributeMap.put("LocalVariableTypeTable", attrMap);
			} else if ("Deprecated".equals(attributeName)) {
//              Deprecated_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attributeMap.put("Deprecated", attrMap);
			} else if ("RuntimeVisibleAnnotations".equals(attributeName)) {
//              RuntimeVisibleAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 num_annotations;
//                  annotation annotations[num_annotations];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeVisibleAnnotations", readRuntimeVisibleAnnotations());

				attributeMap.put("RuntimeVisibleAnnotations", attrMap);
			} else if ("RuntimeInvisibleAnnotations".equals(attributeName)) {
//              RuntimeInvisibleAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 num_annotations;
//                  annotation annotations[num_annotations];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeInvisibleAnnotations", readRuntimeVisibleAnnotations());

				attributeMap.put("RuntimeInvisibleAnnotations", attrMap);
			} else if ("RuntimeVisibleParameterAnnotations".equals(attributeName)) {
//              RuntimeVisibleParameterAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u1 num_parameters;
//                  { u2 num_annotations;
//                      annotation annotations[num_annotations];
//                  } parameter_annotations[num_parameters];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeVisibleParameterAnnotations", readParametersAnnotations());

				attributeMap.put("RuntimeVisibleParameterAnnotations", attrMap);
			} else if ("RuntimeInvisibleParameterAnnotations".equals(attributeName)) {
//              RuntimeInvisibleParameterAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u1 num_parameters;
//                  { u2 num_annotations;
//                      annotation annotations[num_annotations];
//                  } parameter_annotations[num_parameters];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeInvisibleParameterAnnotations", readParametersAnnotations());

				attributeMap.put("RuntimeInvisibleParameterAnnotations", attrMap);
			} else if ("RuntimeVisibleTypeAnnotations".equals(attributeName)) {
//              RuntimeVisibleTypeAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 num_annotations;
//                  type_annotation annotations[num_annotations];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeVisibleTypeAnnotations", readTypeAnnotation(false));

				attributeMap.put("RuntimeVisibleTypeAnnotations", attrMap);
			} else if ("RuntimeInvisibleTypeAnnotations".equals(attributeName)) {
//              RuntimeInvisibleTypeAnnotations_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 num_annotations;
//                  type_annotation annotations[num_annotations];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("runtimeInvisibleTypeAnnotations", readTypeAnnotation(true));

				attributeMap.put("RuntimeInvisibleTypeAnnotations", attrMap);
			} else if ("AnnotationDefault".equals(attributeName)) {
//              AnnotationDefault_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  element_value default_value;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// element_value value;
				attrMap.put("elementTypeMap", readAnnotationElementType());

				attributeMap.put("AnnotationDefault", attrMap);
			} else if ("BootstrapMethods".equals(attributeName)) {
//              BootstrapMethods_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 num_bootstrap_methods;
//                  { u2 bootstrap_method_ref;
//                      u2 num_bootstrap_arguments;
//                      u2 bootstrap_arguments[num_bootstrap_arguments];
//                  } bootstrap_methods[num_bootstrap_methods];
//              }

				// u2 num_bootstrap_methods;
				int numBootstrapMethods = dis.readUnsignedShort();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("numBootstrapMethods", numBootstrapMethods);

				List<Map<String, Object>> bootstrapMethodList = new ArrayList<>();

				for (int i = 0; i < numBootstrapMethods; i++) {
					Map<String, Object> bootstrapMethodMap = new LinkedHashMap<>();
					List<Object>        argumentList       = new ArrayList<>();

					// u2 bootstrap_method_ref;
					bootstrapMethodMap.put("bootstrapMethodRef", getConstantPoolValue(dis.readUnsignedShort()));

					// u2 num_bootstrap_arguments;
					int numBootstrapArguments = dis.readUnsignedShort();
					bootstrapMethodMap.put("numBootstrapArguments", numBootstrapArguments);

					// u2 bootstrap_arguments[num_bootstrap_arguments];
					for (int k = 0; k < numBootstrapArguments; k++) {
						int index = dis.readUnsignedShort();
						argumentList.add(getConstantPoolValue(index));
					}

					bootstrapMethodMap.put("argumentList", argumentList);

					bootstrapMethodList.add(bootstrapMethodMap);
				}

				// 特殊处理CONSTANT_DYNAMIC和CONSTANT_INVOKE_DYNAMIC，反向关联修改常量池中的bootstrapMethodAttrIdx值
				for (Integer id : constantPoolMap.keySet()) {
					Map<String, Object> map  = constantPoolMap.get(id);
					Constant            type = (Constant) map.get("tag");

					if (CONSTANT_DYNAMIC == type || CONSTANT_INVOKE_DYNAMIC == type) {
						Integer bootstrapMethodAttrIdx = (Integer) map.get("bootstrapMethodAttrIdx");

						map.put("bootstrapMethodAttrVal", bootstrapMethodList.get(bootstrapMethodAttrIdx));
					}
				}

				attrMap.put("bootstrapMethodList", bootstrapMethodList);

				attributeMap.put("BootstrapMethods", attrMap);
			} else if ("MethodParameters".equals(attributeName)) {
//              MethodParameters_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u1 parameters_count;
//                  { u2 name_index;
//                      u2 access_flags;
//                  } parameters[parameters_count];
//              }

				// u1 parameters_count;
				int parametersCount = dis.readUnsignedByte();

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();
				attrMap.put("parametersCount", parametersCount);

				List<Map<String, Object>> parameterList = new ArrayList<>();

				// parameters[parameters_count];
				for (int i = 0; i < parametersCount; i++) {
					Map<String, Object> parameterMap = new LinkedHashMap<>();

					// u2 name_index;
					parameterMap.put("name", getConstantPoolValue(dis.readUnsignedShort()));

					// u2 access_flags;
					parameterMap.put("accessFlags", dis.readUnsignedShort());

					parameterList.add(parameterMap);
				}

				attrMap.put("parameterList", parameterList);

				attributeMap.put("MethodParameters", attrMap);
			} else if ("Module".equals(attributeName)) {
//              Module_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 module_name_index;
//                  u2 module_flags;
//                  u2 module_version_index;
//                  u2 requires_count;
//                  { u2 requires_index;
//                      u2 requires_flags;
//                      u2 requires_version_index;
//                  } requires[requires_count];
//                  u2 exports_count;
//                  { u2 exports_index;
//                      u2 exports_flags;
//                      u2 exports_to_count;
//                      u2 exports_to_index[exports_to_count];
//                  } exports[exports_count];
//                  u2 opens_count;
//                  { u2 opens_index;
//                      u2 opens_flags;
//                      u2 opens_to_count;
//                      u2 opens_to_index[opens_to_count];
//                  } opens[opens_count];
//                  u2 uses_count;
//                  u2 uses_index[uses_count];
//                  u2 provides_count;
//                  { u2 provides_index;
//                      u2 provides_with_count;
//                      u2 provides_with_index[provides_with_count];
//                  } provides[provides_count];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 module_name_index;
				attrMap.put("moduleNameIndex", dis.readUnsignedShort());

				// u2 module_flags;
				attrMap.put("moduleFlags", dis.readUnsignedShort());

				// u2 module_version_index;
				attrMap.put("moduleVersionIndex", dis.readUnsignedShort());

				// u2 requires_count;
				int requiresCount = dis.readUnsignedShort();

				attrMap.put("requiresCount", requiresCount);

				List<Map<String, Object>> requiresList = new ArrayList<>();

				// requires[requires_count];
				for (int i = 0; i < requiresCount; i++) {
					Map<String, Object> requiresMap = new LinkedHashMap<>();

					// u2 requires_index;
					requiresMap.put("requiresIndex", dis.readUnsignedShort());

					// u2 requires_flags;
					requiresMap.put("requiresFlags", dis.readUnsignedShort());

					// u2 requires_version_index;
					requiresMap.put("requiresVersionIndex", dis.readUnsignedShort());

					requiresList.add(requiresMap);
				}

				attrMap.put("requiresList", requiresList);

				// u2 exports_count;
				int exportsCount = dis.readUnsignedShort();
				attrMap.put("exportsCount", exportsCount);

				List<Map<String, Object>> exportsList = new ArrayList<>();

				// exports[exports_count];
				for (int i = 0; i < exportsCount; i++) {
					Map<String, Object> exportsMap = new LinkedHashMap<>();

					// u2 exports_index;
					exportsMap.put("exportsIndex", dis.readUnsignedShort());

					// u2 exports_flags;
					exportsMap.put("exportsFlags", dis.readUnsignedShort());

					// u2 exports_to_count;
					int exportsToCount = dis.readUnsignedShort();
					exportsMap.put("exportsToCount", exportsToCount);

					List<Object> exportsToIndexList = new ArrayList<>();

					// u2 exports_to_index[exports_to_count];
					for (int k = 0; k < exportsToCount; k++) {
						exportsToIndexList.add(dis.readUnsignedShort());
					}

					exportsMap.put("exportsToIndexList", exportsToIndexList);

					exportsList.add(exportsMap);
				}

				attrMap.put("exportsList", exportsList);

				// u2 opens_count;
				int opensCount = dis.readUnsignedShort();
				attrMap.put("opensCount", opensCount);

				List<Map<String, Object>> opensList = new ArrayList<>();

				for (int i = 0; i < opensCount; i++) {
					Map<String, Object> opensMap = new LinkedHashMap<>();

					// u2 opens_index;
					opensMap.put("opensIndex", dis.readUnsignedShort());

					// u2 opens_flags;
					opensMap.put("opensFlags", dis.readUnsignedShort());

					// u2 opens_to_count;
					int opensToCount = dis.readUnsignedShort();
					opensMap.put("opensToCount", opensToCount);

					List<Object> opensToIndexList = new ArrayList<>();

					// u2 opens_to_index[opens_to_count];
					for (int k = 0; k < opensToCount; k++) {
						opensToIndexList.add(dis.readUnsignedShort());
					}

					opensMap.put("opensToIndexList", opensToIndexList);

					opensList.add(opensMap);
				}

				attrMap.put("opensList", opensList);

				// u2 uses_count;
				int usesCount = dis.readUnsignedShort();
				attrMap.put("usesCount", usesCount);

				List<Object> usesIndexList = new ArrayList<>();

				// u2 uses_index[uses_count];
				for (int i = 0; i < usesCount; i++) {
					usesIndexList.add(dis.readUnsignedShort());
				}

				attrMap.put("usesIndexList", usesIndexList);

				// u2 provides_count;
				int providesCount = dis.readUnsignedShort();
				attrMap.put("providesCount", providesCount);

				List<Map<String, Object>> providesList = new ArrayList<>();

				// provides[provides_count];
				for (int i = 0; i < providesCount; i++) {
					Map<String, Object> opensMap = new LinkedHashMap<>();

					// u2 provides_index;
					opensMap.put("providesIndex", dis.readUnsignedShort());

					// u2 provides_with_count;
					int providesWithCount = dis.readUnsignedShort();
					opensMap.put("providesWithCount", providesWithCount);

					List<Object> providesWithIndexList = new ArrayList<>();

					// u2 provides_with_index[provides_with_count];
					for (int k = 0; k < providesWithCount; k++) {
						providesWithIndexList.add(dis.readUnsignedShort());
					}

					opensMap.put("providesWithIndexList", providesWithIndexList);

					providesList.add(opensMap);
				}

				attrMap.put("providesList", providesList);
				attributeMap.put("Module", attrMap);
			} else if ("ModulePackages".equals(attributeName)) {
//              ModulePackages_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 package_count;
//                  u2 package_index[package_count];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 package_count;
				int packageCount = dis.readUnsignedShort();
				attributeMap.put("packageCount", packageCount);

				// u2 package_index[package_count];
				List<Object> packageList = new ArrayList<>();

				for (int i = 0; i < packageCount; i++) {
					packageList.add(getConstantPoolValue(dis.readUnsignedShort()));
				}

				attrMap.put("packageList", packageList);

				attributeMap.put("ModulePackages", attrMap);
			} else if ("ModuleMainClass".equals(attributeName)) {
//              ModuleMainClass_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 main_class_index;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 main_class_index;
				attrMap.put("mainClassIndex", dis.readUnsignedShort());
				attributeMap.put("ModuleMainClass", attrMap);
			} else if ("NestHost".equals(attributeName)) {
//              NestHost_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 host_class_index;
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 host_class_index;
				attrMap.put("hostClassIndex", dis.readUnsignedShort());
				attributeMap.put("NestHost", attrMap);
			} else if ("NestMembers".equals(attributeName)) {
//              NestMembers_attribute {
//                  u2 attribute_name_index;
//                  u4 attribute_length;
//                  u2 number_of_classes;
//                  u2 classes[number_of_classes];
//              }

				// 创建属性Map
				Map<String, Object> attrMap = new LinkedHashMap<>();

				// u2 number_of_classes;
				int numberOfClasses = dis.readUnsignedShort();
				attrMap.put("numberOfClasses", numberOfClasses);

				int[] classes = new int[numberOfClasses];

				for (int i = 0; i < numberOfClasses; i++) {
					classes[i] = dis.readUnsignedShort();
				}

				attrMap.put("classes", classes);
				attributeMap.put("NestMembers", attrMap);
			}
		}

		return attributeMap;
	}

	private void addOpcodes(List<String> opcodeList, Opcodes opcode, int val) {
		Object value = getConstantPoolValue(val);

		if (value != null) {
			opcodeList.add(opcode.getDesc() + " " + "#" + val + " <" + value + ">");
		} else {
			opcodeList.add(opcode.getDesc() + " " + val);
		}
	}

	/**
	 * 读取栈指令中的无用padding
	 *
	 * @param bytes
	 * @param dis
	 * @return
	 * @throws IOException
	 */
	private int readPaddingBytes(byte[] bytes, DataInputStream dis) throws IOException {
		int bytesCount = bytes.length - dis.available();
		int bytesToPad = 4 - bytesCount % 4;

		int bytesToRead = (bytesToPad == 4) ? 0 : bytesToPad;

		for (int i = 0; i < bytesToRead; i++) {
			dis.readByte();
		}

		return bytesToRead;
	}

	/**
	 * 读取RuntimeVisibleAnnotations
	 *
	 * @return attrMap
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readRuntimeVisibleAnnotations() throws IOException {
		// 创建属性Map
		Map<String, Object> attrMap = new LinkedHashMap<>();

		// u2 num_annotations;
		int numAnnotations = dis.readUnsignedShort();
		attrMap.put("numAnnotations", numAnnotations);

		List<Map<String, Object>> annotationList = new ArrayList<>();

		// annotation annotations[num_annotations];
		for (int i = 0; i < numAnnotations; i++) {
			annotationList.add(readAnnotation());
		}

		attrMap.put("annotationList", annotationList);

		return attrMap;
	}

	/**
	 * 读取参数的注解
	 *
	 * @return attrMap
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readParametersAnnotations() throws IOException {
		// 创建属性Map
		Map<String, Object> attrMap = new LinkedHashMap<>();

		// u1 num_parameters;
		int numParameters = dis.readUnsignedByte();
		attrMap.put("numParameters", numParameters);

		List<Map<String, Object>> parameterList = new ArrayList<>();

		// parameter_annotations[num_parameters];
		for (int i = 0; i < numParameters; i++) {
			// u2 num_annotations;
			int numAnnotations = dis.readUnsignedShort();

			List<Map<String, Object>> annotationList = new ArrayList<>();
			Map<String, Object>       parameterMap   = new LinkedHashMap<>();
			parameterMap.put("numAnnotations", numAnnotations);

			// annotation annotations[num_annotations];
			for (int k = 0; k < numAnnotations; k++) {
				annotationList.add(readAnnotation());
			}

			parameterMap.put("annotationList", annotationList);

			parameterList.add(parameterMap);
		}

		attrMap.put("parameterList", parameterList);

		return attrMap;
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
	 * 读取注解
	 *
	 * @return annotationMap
	 * @throws IOException 读取异常
	 */
	private Map<String, Object> readAnnotation() throws IOException {
//      annotation {
//          u2 type_index;
//          u2 num_element_value_pairs;
//          { u2 element_name_index;
//              element_value value;
//          } element_value_pairs[num_element_value_pairs];
//      }

		Map<String, Object> annotationMap = new LinkedHashMap<>();

		// u2 type_index;
		annotationMap.put("type", getConstantPoolValue(dis.readUnsignedShort()));

		// element_value_pairs[num_element_value_pairs];
		annotationMap.put("elementvaluepairs", readAnnotationElementValuePairs());

		return annotationMap;
	}

	private Map<String, Object> readAnnotationElementValuePairs() throws IOException {
		Map<String, Object> annotationMap = new LinkedHashMap<>();

		// u2 num_element_value_pairs;
		int numElementValuePairs = dis.readUnsignedShort();
		annotationMap.put("numElementValuePairs", numElementValuePairs);

		List<Map<String, Object>> elementValueList = new ArrayList<>();

		// element_value_pairs[num_element_value_pairs];
		for (int i = 0; i < numElementValuePairs; i++) {
			Map<String, Object> elementValueMap = new LinkedHashMap<>();

			// u2 element_name_index;
			elementValueMap.put("elementName", getConstantPoolValue(dis.readUnsignedShort()));

			// element_value value;
			elementValueMap.put("elementTypeMap", readAnnotationElementType());

			elementValueList.add(elementValueMap);
		}

		annotationMap.put("elementValueList", elementValueList);

		return annotationMap;
	}

	private Map<String, Object> readTypeAnnotation(boolean isInvisible) throws IOException {
		// u2 num_annotations;
		int numAnnotations = dis.readUnsignedShort();

		// 创建属性Map
		Map<String, Object> attrMap = new LinkedHashMap<>();
		attrMap.put("numAnnotations", numAnnotations);

		List<Map<String, Object>> typeAnnotationList = new ArrayList<>();

		// type_annotation annotations[num_annotations];
		for (int i = 0; i < numAnnotations; i++) {
//          type_annotation {
//              u1 target_type;
//              union {
//                  type_parameter_target;
//                  supertype_target;
//                  type_parameter_bound_target;
//                  empty_target;
//                  formal_parameter_target;
//                  throws_target;
//                  localvar_target;
//                  catch_target;
//                  offset_target;
//                  type_argument_target;
//              } target_info;
//              type_path target_path;
//              u2 type_index;
//              u2 num_element_value_pairs;
//              { u2 element_name_index;
//                  element_value value;
//              } element_value_pairs[num_element_value_pairs];
//          }

			Map<String, Object> typeAnnotationMap = new LinkedHashMap<>();

			// u1 target_type;
			int tag = dis.readUnsignedByte();
			typeAnnotationMap.put("targetType", tag);

			// Table 4.7.20-A/B. Interpretation of target_type values
			// Value    Kind of target                                                                                          target_info item
			// 0x00     type parameter declaration of generic class  or interface                                               type_parameter_target
			// 0x01     type parameter declaration of generic method or constructor                                             type_parameter_target
			// 0x10     type in extends or implements clause of class declaration (including the direct superclass or direct superinterface of an anonymous class declaration), or in extends clause of interface declaration   supertype_target
			// 0x11     type in bound of type parameter declaration of generic class or interface                               type_parameter_bound_target
			// 0x12     type in bound of type parameter declaration of generic method or constructor                            type_parameter_bound_target
			// 0x13     type in field declaration                                                                               empty_target
			// 0x14     return type of method, or type of newly constructed object                                              empty_target
			// 0x15     receiver type of method or constructor                                                                  empty_target
			// 0x16     type in formal parameter declaration of method, constructor, or lambda expression                       formal_parameter_target
			// 0x17     type in throws clause of method or constructor                                                          throws_target
			// 0x40     type in local variable declaration                                                                      localvar_target
			// 0x41     type in resource variable declaration                                                                   localvar_target
			// 0x42     type in exception parameter declaration                                                                 catch_target
			// 0x43     type in instanceof expression                                                                           offset_target
			// 0x44     type in new expression                                                                                  offset_target
			// 0x45     type in method reference expression using ::new                                                         offset_target
			// 0x46     type in method reference expression using ::Identifier                                                  offset_target
			// 0x47     type in cast expression                                                                                 type_argument_target
			// 0x48     type argument for generic constructor in new expression or explicit constructor invocation statement    type_argument_target
			// 0x49     type argument for generic method in method invocation expression                                        type_argument_target
			// 0x4A     type argument for generic constructor in method reference expression using ::new                        type_argument_target
			// 0x4B     type argument for generic method in method reference expression using ::Identifier                      type_argument_target

			// Table 4.7.20-C. Location of enclosing attribute for target_type values
			// Value        Kind of target                                                                                                          Location
			// 0x00         type parameter declaration of generic class or interface                                                                ClassFile
			// 0x01         type parameter declaration of generic method or constructor                                                             method_info
			// 0x10         type in extends clause of class or interface declaration, or in implements clause of interface declaration              ClassFile
			// 0x11         type in bound of type parameter declaration of generic class or interface                                               ClassFile
			// 0x12         type in bound of type parameter declaration of generic method or constructor                                            method_info
			// 0x13         type in field declaration                                                                                               field_info
			// 0x14         return type of method or constructor                                                                                    method_info
			// 0x15         receiver type of method or constructor                                                                                  method_info
			// 0x16         type in formal parameter declaration of method, constructor, or lambda expression                                       method_info
			// 0x17         type in throws clause of method or constructor                                                                          method_info
			// 0x40-0x4B    types in local variable declarations, resource variable declarations, exception parameter declarations, expressions     Code

			if (isInvisible) {
				if (tag == 0x00 || tag == 0x01) {
//                  type_parameter_target {
//                      u1 type_parameter_index;
//                  }

					int typeParameterTarget = dis.readUnsignedByte();
				} else if (tag == 0x10) {
//                  supertype_target {
//                      u2 supertype_index;
//                  }

					int superTypeTarget = dis.readUnsignedShort();
				} else if (tag == 0x11 || tag == 0x12) {
//                  type_parameter_bound_target {
//                      u1 type_parameter_index;
//                      u1 bound_index;
//                  }

					int typeParameterIndex = dis.readUnsignedByte();
					int boundIndex         = dis.readUnsignedByte();
				} else if (tag == 0x13 || tag == 0x14 || tag == 0x15) {
//                  empty_target {
//                  }
				} else if (tag == 0x16) {
//                  formal_parameter_target {
//                      u1 formal_parameter_index;
//                  }

					int formalParameterTarget = dis.readUnsignedByte();
				} else if (tag == 0x17) {
//                  throws_target {
//                      u2 throws_type_index;
//                  }

					int throwsTarget = dis.readUnsignedShort();
				} else if (tag == 0x40 || tag == 0x41) {
//                  localvar_target {
//                      u2 table_length;
//                      { u2 start_pc;
//                          u2 length;
//                          u2 index;
//                      } table[table_length];
//                  }

					// u2 table_length;
					int tableLength = dis.readUnsignedShort();

					for (int k = 0; k < tableLength; k++) {
						// u2 start_pc
						int startPc = dis.readUnsignedShort();

						// u2 length
						int length = dis.readUnsignedShort();

						// u2 index;
						int index = dis.readUnsignedShort();
					}
				} else if (tag == 0x42) {
//                  catch_target {
//                      u2 exception_table_index;
//                  }

					int exceptionTableIndex = dis.readUnsignedShort();
				} else if (tag == 0x43 || tag == 0x44 || tag == 0x45 || tag == 0x46) {
//                  offset_target {
//                      u2 offset;
//                  }

					// u2 offset;
					int offset = dis.readUnsignedShort();
				} else if (tag == 0x47 || tag == 0x48 || tag == 0x49 || tag == 0x4A || tag == 0x4B) {
//                  type_argument_target {
//                      u2 offset;
//                      u1 type_argument_index;
//                  }

					// u2 offset;
					int offset = dis.readUnsignedShort();

					// u1 type_argument_index;
					int typeArgumentIndex = dis.readUnsignedByte();
				}
			} else {
				if (tag == 0x00) {

				} else if (tag == 0x01) {

				} else if (tag == 0x10 || tag == 0x11) {

				} else if (tag == 0x13) {

				} else if (tag == 0x12 || tag == 0x14 || tag == 0x15 || tag == 0x16 || tag == 0x17) {

				} else if (tag == 0x40 || tag == 0x41 || tag == 0x42 || tag == 0x43 || tag == 0x44 || tag == 0x45 ||
						tag == 0x46 || tag == 0x47 || tag == 0x48 || tag == 0x49 || tag == 0x4A || tag == 0x4B) {

				}
			}

			// type_path target_path;
//          type_path {
//              u1 path_length;
//              { u1 type_path_kind;
//                  u1 type_argument_index;
//              } path[path_length];
//          }

			// u1 path_length;
			int pathLength = dis.readUnsignedByte();
			typeAnnotationMap.put("pathLength", pathLength);

			// path[path_length];
			for (int k = 0; k < pathLength; k++) {
				// u1 type_path_kind;
				int typePathKind = dis.readUnsignedByte();

				// u1 type_argument_index;
				int typeArgumentIndex = dis.readUnsignedByte();
			}

			// u2 type_index;
			typeAnnotationMap.put("typeIndex", dis.readUnsignedShort());

			// u2 num_element_value_pairs;
			int numElementValuePairs = dis.readUnsignedShort();
			typeAnnotationMap.put("numElementValuePairs", numElementValuePairs);

			List<Map<String, Object>> elementValuePairsList = new ArrayList<>();

			// element_value_pairs[num_element_value_pairs];
			for (int k = 0; k < numElementValuePairs; k++) {
				Map<String, Object> elementValuePairsMap = new LinkedHashMap<>();

				// u2 element_name_index;
				int elementNameIndex = dis.readUnsignedShort();
				elementValuePairsMap.put("elementNameIndex", elementNameIndex);

				// element_value value;
//              element_value {
//                  u1 tag;
//                  union {
//                      u2 const_value_index;
//                      { u2 type_name_index;
//                          u2 const_name_index;
//                      } enum_const_value;
//                      u2 class_info_index;
//                      annotation annotation_value;
//                      { u2 num_values;
//                          element_value values[num_values];
//                      } array_value;
//                  } value;
//              }

				elementValuePairsMap.put("annotationElementType", readAnnotationElementType());

				elementValuePairsList.add(elementValuePairsMap);
			}

			typeAnnotationMap.put("elementValuePairsList", elementValuePairsList);

			typeAnnotationList.add(typeAnnotationMap);
		}

		attrMap.put("typeAnnotationList", typeAnnotationList);

		return attrMap;
	}

	private Map<String, Object> readAnnotationElementType() throws IOException {
		Map<String, Object> elementTypeMap = new LinkedHashMap<>();

//          element_value {
//              u1 tag;
//              union {
//                  u2 const_value_index;
//                  { u2 type_name_index;
//                      u2 const_name_index;
//                  } enum_const_value;
//                  u2 class_info_index;
//                  annotation annotation_value;
//                  { u2 num_values;
//                      element_value values[num_values];
//                  } array_value;
//              } value;
//          }

		char tag = (char) dis.readUnsignedByte();
		elementTypeMap.put("tag", tag);

		// tag Item Type                value Item           Constant Type
		// B        byte                const_value_index    CONSTANT_Integer
		// C        char                const_value_index    CONSTANT_Integer
		// D        double              const_value_index    CONSTANT_Double
		// F        float               const_value_index    CONSTANT_Float
		// I        int                 const_value_index    CONSTANT_Integer
		// J        long                const_value_index    CONSTANT_Long
		// S        short               const_value_index    CONSTANT_Integer
		// Z        boolean             const_value_index    CONSTANT_Integer
		// s        String              const_value_index    CONSTANT_Utf8
		// e        Enum type           enum_const_value     Not applicable
		// c        Class               class_info_index     Not applicable
		// @        Annotation type     annotation_value     Not applicable
		// [        Array type          array_value          Not applicable
		if (tag == 'B' || tag == 'C' || tag == 'D' || tag == 'F' || tag == 'I' ||
				tag == 'J' || tag == 'S' || tag == 'Z' || tag == 's') {

			elementTypeMap.put("constValue", getConstantPoolValue(dis.readUnsignedShort()));
		} else if (tag == 'e') {
			elementTypeMap.put("typeName", getConstantPoolValue(dis.readUnsignedShort()));
			elementTypeMap.put("constName", getConstantPoolValue(dis.readUnsignedShort()));
		} else if (tag == 'c') {
			elementTypeMap.put("classInfo", getConstantPoolValue(dis.readUnsignedShort()));
		} else if (tag == '@') {
			elementTypeMap.put("type", getConstantPoolValue(dis.readUnsignedShort()));

			elementTypeMap.put("elementValueList", readAnnotationElementValuePairs());
		} else if (tag == '[') {
			int numValues = dis.readUnsignedShort();
			elementTypeMap.put("numValues", numValues);

			List<Map<String, Object>> elementValueList = new ArrayList<>();

			for (int j = 0; j < numValues; j++) {
				Map<String, Object> elementValueMap = new LinkedHashMap<>();

				// element_value value;
				elementValueMap.put("elementTypeMap", readAnnotationElementType());

				elementValueList.add(elementValueMap);
			}

			elementTypeMap.put("elementValueList", elementValueList);
		}

		return elementTypeMap;
	}

	private Map<String, Object> readVerificationTypeInfo() throws IOException {
		int tag = dis.readUnsignedByte();

		Map<String, Object> typeInfoMap = new LinkedHashMap<>();
		typeInfoMap.put("tag", tag);

//      union verification_type_info {
//          Top_variable_info;
//          Integer_variable_info;
//          Float_variable_info;
//          Long_variable_info;
//          Double_variable_info;
//          Null_variable_info;
//          UninitializedThis_variable_info;
//          Object_variable_info;
//          Uninitialized_variable_info;
//      }

		if (tag == 0) {
			// Top_variable_info
		} else if (tag == 1) {
			// Integer_variable_info
		} else if (tag == 2) {
			// Float_variable_info
		} else if (tag == 3) {
			// Double_variable_info
		} else if (tag == 4) {
			// Long_variable_info
		} else if (tag == 5) {
			// Null_variable_info
		} else if (tag == 6) {
			// UninitializedThis_variable_info
		} else if (tag == 7) {
			// Object_variable_info
			int poolIndex = dis.readUnsignedShort();

			typeInfoMap.put("poolIndex", poolIndex);
		} else if (tag == 8) {
			// Uninitialized_variable_info
			int offset = dis.readUnsignedShort();
			typeInfoMap.put("offset", offset);
		}

		return typeInfoMap;
	}

	/**
	 * 链接常量池中的引用
	 */
	private void linkConstantPool() {
		for (Integer id : constantPoolMap.keySet()) {
			Map<String, Object> valueMap = constantPoolMap.get(id);

			if (!valueMap.containsKey("value")) {
				Map<String, Object> newMap = new LinkedHashMap<>();

				for (String key : valueMap.keySet()) {
					if (key.endsWith("Index")) {
						Object value = recursionValue((Integer) valueMap.get(key));

						if (value != null) {
							String newKey = key.substring(0, key.indexOf("Index"));

							newMap.put(newKey + "Value", value);
						}
					}
				}

				valueMap.putAll(newMap);
			}
		}
	}

	/**
	 * 递归查找ID对应的常量池中的值
	 *
	 * @param id 常量池ID
	 * @return 常量池中存储的值
	 */
	private Object recursionValue(Integer id) {
		Map<String, Object> map = constantPoolMap.get(id);

		if (map.containsKey("value")) {
			return map.get("value");
		}

		for (String key : map.keySet()) {
			if (key.endsWith("Index")) {
				Integer value = (Integer) map.get(key);

				return recursionValue(value);
			}
		}

		return null;
	}

	/**
	 * 解析常量池数据
	 *
	 * @throws IOException 数据读取异常
	 */
	private void parseConstantPool() throws IOException {
		// u2 constant_pool_count;
		this.poolCount = dis.readUnsignedShort();

		// cp_info constant_pool[constant_pool_count-1];
		for (int i = 1; i <= poolCount - 1; i++) {
//          cp_info {
//              u1 tag;
//              u1 info[];
//          }

			int      tag      = dis.readUnsignedByte();
			Constant constant = Constant.getConstant(tag);

			if (constant == null) {
				throw new RuntimeException("解析常量池异常，无法识别的常量池类型：" + tag);
			}

			// 解析常量池对象
			parseConstantItems(constant, i);

			// Long和Double是宽类型，占两位
			if (CONSTANT_LONG == constant || CONSTANT_DOUBLE == constant) {
				i++;
			}
		}

		// 链接常量池中的引用
		linkConstantPool();
	}

	/**
	 * 解析常量池中的对象
	 *
	 * @param constant 常量池
	 * @param index    常量池中的索引位置
	 * @throws IOException 数据读取异常
	 */
	private void parseConstantItems(Constant constant, int index) throws IOException {
		Map<String, Object> map = new LinkedHashMap<>();

		switch (constant) {
			case CONSTANT_UTF8:
//                  CONSTANT_Utf8_info {
//                      u1 tag;
//                      u2 length;
//                      u1 bytes[length];
//                  }

				int length = dis.readUnsignedShort();
				byte[] bytes = new byte[length];
				dis.read(bytes);

				map.put("tag", CONSTANT_UTF8);
				map.put("value", new String(bytes, UTF_8));
				break;
			case CONSTANT_INTEGER:
//                  CONSTANT_Integer_info {
//                      u1 tag;
//                      u4 bytes;
//                  }

				map.put("tag", CONSTANT_INTEGER);
				map.put("value", dis.readInt());
				break;
			case CONSTANT_FLOAT:
//                  CONSTANT_Float_info {
//                      u1 tag;
//                      u4 bytes;
//                  }

				map.put("tag", CONSTANT_FLOAT);
				map.put("value", dis.readFloat());
				break;
			case CONSTANT_LONG:
//                  CONSTANT_Long_info {
//                      u1 tag;
//                      u4 high_bytes;
//                      u4 low_bytes;
//                  }

				map.put("tag", CONSTANT_LONG);
				map.put("value", dis.readLong());
				break;
			case CONSTANT_DOUBLE:
//                  CONSTANT_Double_info {
//                      u1 tag;
//                      u4 high_bytes;
//                      u4 low_bytes;
//                  }

				map.put("tag", CONSTANT_DOUBLE);
				map.put("value", dis.readDouble());
				break;
			case CONSTANT_CLASS:
//                  CONSTANT_Class_info {
//                      u1 tag;
//                      u2 name_index;
//                  }

				map.put("tag", CONSTANT_CLASS);
				map.put("nameIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_STRING:
//                  CONSTANT_String_info {
//                      u1 tag;
//                      u2 string_index;
//                  }

				map.put("tag", CONSTANT_STRING);
				map.put("stringIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_FIELD_REF:
//                  CONSTANT_Fieldref_info {
//                      u1 tag;
//                      u2 class_index;
//                      u2 name_and_type_index;
//                  }

				map.put("tag", CONSTANT_FIELD_REF);
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_METHOD_REF:
//                  CONSTANT_Methodref_info {
//                      u1 tag;
//                      u2 class_index;
//                      u2 name_and_type_index;
//                  }

				map.put("tag", CONSTANT_METHOD_REF);
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_INTERFACE_METHOD_REF:
//                  CONSTANT_InterfaceMethodref_info {
//                      u1 tag;
//                      u2 class_index;
//                      u2 name_and_type_index;
//                  }

				map.put("tag", CONSTANT_INTERFACE_METHOD_REF);
				map.put("classIndex", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_NAME_AND_TYPE:
//                  CONSTANT_NameAndType_info {
//                      u1 tag;
//                      u2 name_index;
//                      u2 descriptor_index;
//                  }

				map.put("tag", CONSTANT_NAME_AND_TYPE);
				map.put("nameIndex", dis.readUnsignedShort());
				map.put("descriptorIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_METHOD_HANDLE:
//                  CONSTANT_MethodHandle_info {
//                      u1 tag;
//                      u1 reference_kind;
//                      u2 reference_index;
//                  }

				map.put("tag", CONSTANT_METHOD_HANDLE);
				map.put("referenceKind", dis.readUnsignedByte());
				map.put("referenceIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_METHOD_TYPE:
//                  CONSTANT_MethodType_info {
//                      u1 tag;
//                      u2 descriptor_index;
//                  }

				map.put("tag", CONSTANT_METHOD_TYPE);
				map.put("descriptorIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_DYNAMIC:
//                  CONSTANT_Dynamic_info {
//                      u1 tag;
//                      u2 bootstrap_method_attr_index;
//                      u2 name_and_type_index;
//                  }

				map.put("tag", CONSTANT_DYNAMIC);
				map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_INVOKE_DYNAMIC:
//                  CONSTANT_InvokeDynamic_info {
//                      u1 tag;
//                      u2 bootstrap_method_attr_index;
//                      u2 name_and_type_index;
//                  }

				map.put("tag", CONSTANT_INVOKE_DYNAMIC);
				map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
				map.put("nameAndTypeIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_MODULE:
//                  CONSTANT_Module_info {
//                      u1 tag;
//                      u2 name_index;
//                  }

				map.put("tag", CONSTANT_MODULE);
				map.put("nameIndex", dis.readUnsignedShort());
				break;
			case CONSTANT_PACKAGE:
//                  CONSTANT_Package_info {
//                      u1 tag;
//                      u2 name_index;
//                  }

				map.put("tag", CONSTANT_PACKAGE);
				map.put("nameIndex", dis.readUnsignedShort());
				break;
		}

		constantPoolMap.put(index, map);
	}

	public int getMagic() {
		return magic;
	}

	public int getMinor() {
		return minor;
	}

	public int getMajor() {
		return major;
	}

	public int getPoolCount() {
		return poolCount;
	}

	public Map<Integer, Map<String, Object>> getConstantPoolMap() {
		return constantPoolMap;
	}

	public int getAccessFlags() {
		return accessFlags;
	}

	public String getThisClass() {
		return thisClass;
	}

	public String getSuperClass() {
		return superClass;
	}

	public int getInterfacesCount() {
		return interfacesCount;
	}

	public String[] getInterfaces() {
		return interfaces;
	}

	public int getFieldsCount() {
		return fieldsCount;
	}

	public Set<Map<String, Object>> getFieldList() {
		return fieldList;
	}

	public int getMethodsCount() {
		return methodsCount;
	}

	public Set<Map<String, Object>> getMethodList() {
		return methodList;
	}

	public int getAttributesCount() {
		return attributesCount;
	}

	public Map<String, Object> getAttributes() {
		return attributes;
	}

	public static void main(String[] args) throws IOException {
		// 解析单个class文件
		File                classFile  = new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/target/classes/com/anbai/sec/bytecode/TestHelloWorld.class");
		ClassByteCodeParser codeParser = new ClassByteCodeParser();

		codeParser.parseByteCode(new FileInputStream(classFile));
		System.out.println(JSON.toJSONString(codeParser));
//
//		// 解析目录下所有的.class文件
//		Collection<File> files = FileUtils.listFiles(new File("/Users/yz/IdeaProjects/anbai-lingxe-cloud/target/classes"), new String[]{"class"}, true);
//
//		for (File file : files) {
//			System.out.println(file);
//			long                ctime  = System.currentTimeMillis();
//			ClassByteCodeParser parser = new ClassByteCodeParser();
//
//			parser.parseByteCode(new FileInputStream(file));
//			System.out.println(JSON.toJSONString(parser));
//			System.out.println(file + "\t" + (System.currentTimeMillis() - ctime));
//		}
	}

}