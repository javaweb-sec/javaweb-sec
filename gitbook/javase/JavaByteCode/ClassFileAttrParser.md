# Java class文件属性解析

class文件的属性解析是非常复杂的，因为属性表由非常多的类型组成，几乎每一个数据类型都不一样，而且属性表是动态的，它还会随着JDK的版本升级而新增属性对象。在class文件中：`成员变量`、`成员方法`、`类`都拥有属性信息，解析的时候可以使用同样的方法。因为属性表中的属性类型过多，本节仅以解析`ConstantValue`、`Code`为例，完整的解析代码请参考[ClassByteCodeParser类](https://github.com/javaweb-sec/javaweb-sec/blob/master/javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/ClassByteCodeParser.java#L570)。

**属性信息表数据结构：**

```
u2 attributes_count;
attribute_info attributes[attributes_count];

attribute_info {
   u2 attribute_name_index;
   u4 attribute_length;
   u1 info[attribute_length];
}
```

`u2 attributes_count;`表示的是属性表的长度，循环所有属性对象可得到`attribute_info`对象。`attribute_info`对象有两个固定的属性值：`u2 attribute_name_index;`（属性名称）和`u4 attribute_length;`（属性的字节长度），我们可以先解析出这两个属性：

```java
// u2 attribute_name_index;
String attributeName = (String) getConstantPoolValue(dis.readUnsignedShort());

// u4 attribute_length;
int attributeLength = dis.readInt();
```

解析出属性名称后就需要参考[JVM虚拟机规范第4.7章-属性](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7)来解析各类属性信息了。

**预定义属性表**

| 属性名称                               | 属性位置                                         | 章节                                                         | Java版本 |
| -------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------ | -------- |
| `ConstantValue`                        | `field_info`                                     | [§4.7.2](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.2) | 1.0.2    |
| `Code`                                 | `method_info`                                    | [§4.7.3](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.3) | 1.0.2    |
| `StackMapTable`                        | `Code`                                           | [§4.7.4](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.4) | 6        |
| `Exceptions`                           | `method_info`                                    | [§4.7.5](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.5) | 1.0.2    |
| `InnerClasses`                         | `ClassFile`                                      | [§4.7.6](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.6) | 1.1      |
| `EnclosingMethod`                      | `ClassFile`                                      | [§4.7.7](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.7) | 5.0      |
| `Synthetic`                            | `ClassFile`, `field_info`, `method_info`         | [§4.7.8](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.8) | 1.1      |
| `Signature`                            | `ClassFile`, `field_info`, `method_info`         | [§4.7.9](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.9) | 5.0      |
| `SourceFile`                           | `ClassFile`                                      | [§4.7.10](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.10) | 1.0.2    |
| `SourceDebugExtension`                 | `ClassFile`                                      | [§4.7.11](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.11) | 5.0      |
| `LineNumberTable`                      | `Code`                                           | [§4.7.12](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.12) | 1.0.2    |
| `LocalVariableTable`                   | `Code`                                           | [§4.7.13](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.13) | 1.0.2    |
| `LocalVariableTypeTable`               | `Code`                                           | [§4.7.14](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.14) | 5.0      |
| `Deprecated`                           | `ClassFile`, `field_info`, `method_info`         | [§4.7.15](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.15) | 1.1      |
| `RuntimeVisibleAnnotations`            | `ClassFile`, `field_info`, `method_info`         | [§4.7.16](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.16) | 5.0      |
| `RuntimeInvisibleAnnotations`          | `ClassFile`, `field_info`, `method_info`         | [§4.7.17](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.17) | 5.0      |
| `RuntimeVisibleParameterAnnotations`   | `method_info`                                    | [§4.7.18](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.18) | 5.0      |
| `RuntimeInvisibleParameterAnnotations` | `method_info`                                    | [§4.7.19](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.19) | 5.0      |
| `RuntimeVisibleTypeAnnotations`        | `ClassFile`, `field_info`, `method_info`, `Code` | [§4.7.20](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.20) | 8        |
| `RuntimeInvisibleTypeAnnotations`      | `ClassFile`, `field_info`, `method_info`, `Code` | [§4.7.21](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.21) | 8        |
| `AnnotationDefault`                    | `method_info`                                    | [§4.7.22](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.22) | 5.0      |
| `BootstrapMethods`                     | `ClassFile`                                      | [§4.7.23](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.23) | 7        |
| `MethodParameters`                     | `method_info`                                    | [§4.7.24](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.24) | 8        |
| `Module`                               | `ClassFile`                                      | [§4.7.25](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.25) | 9        |
| `ModulePackages`                       | `ClassFile`                                      | [§4.7.26](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.26) | 9        |
| `ModuleMainClass`                      | `ClassFile`                                      | [§4.7.27](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.27) | 9        |
| `NestHost`                             | `ClassFile`                                      | [§4.7.28](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.28) | 11       |
| `NestMembers`                          | `ClassFile`                                      | [§4.7.29](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.7.29) | 11       |

## ConstantValue

`ConstantValue`属性用于表示`field_info`中的静态变量的初始值，结构如下：

```
ConstantValue_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 constantvalue_index;
}
```

**ConstantValue解析代码片段：**

```java
// 创建属性Map
Map<String, Object> attrMap = new LinkedHashMap<>();

// u2 constantvalue_index;
attrMap.put("constantValue", getConstantPoolValue(dis.readUnsignedShort()));

attributeMap.put("ConstantValue", attrMap);
```

解析后的结果如下：

```json
{
  "access": 26, 
  "name": "serialVersionUID", 
  "desc": "J", 
  "attributesCount": 1, 
  "attributes": {
    "attributeName": "ConstantValue", 
    "attributeLength": 2, 
    "ConstantValue": {
      "constantValue": -7366591802115334000
    }
  }
}
```

## Code

`Code`属性用于表示成员方法的代码部分，`Code`中包含了指令集（`byte数组`），JVM调用成员方法时实际上就是执行的`Code`中的指令，而反编译工具则是把`Code`中的指令翻译成了Java代码。

```
Code_attribute {
  u2 attribute_name_index;
  u4 attribute_length;
  u2 max_stack;
  u2 max_locals;
  u4 code_length;
  u1 code[code_length];
  u2 exception_table_length;
  { u2 start_pc;
   u2 end_pc;
   u2 handler_pc;
   u2 catch_type;
  } exception_table[exception_table_length];
  u2 attributes_count;
  attribute_info attributes[attributes_count];
}
```

**Code解析代码片段：**

```java
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
```

在解析`Code`属性时`code_length`表示的是`Code`的字节长度，`max_stack`和`max_locals`是一个固定值，表示的是最大操作数栈和最大局部变量数，这两个值是在编译类方法时自动计算出来的，如果通过`ASM`修改了类方法可能会需要重新计算`max_stack`和`max_locals`。

**示例 - TestHelloWorld类Hello方法解析结果：**

```json
{
  "access": 1, 
  "name": "hello", 
  "desc": "(Ljava/lang/String;)Ljava/lang/String;", 
  "attributesCount": 1, 
  "attributes": {
    "attributeName": "Code", 
    "attributeLength": 88, 
    "Code": {
      "maxStack": 2, 
      "maxLocals": 3, 
      "codeLength": 22, 
      "opcodes": [
        "ldc #3 <Hello:>", 
        "astore_2", 
        "new #4 <java/lang/StringBuilder>", 
        "dup", 
        "invokespecial #5 <java/lang/StringBuilder.<init>>", 
        "aload_2", 
        "invokevirtual #6 <java/lang/StringBuilder.append>", 
        "aload_1", 
        "invokevirtual #6 <java/lang/StringBuilder.append>", 
        "invokevirtual #7 <java/lang/StringBuilder.toString>", 
        "areturn"
      ], 
      "exceptionTable": {
        "exceptionTableLength": 0, 
        "exceptionTableList": [ ]
      }, 
      "attributeLength": 88, 
      "attributes": {
        "attributeName": "LocalVariableTable", 
        "attributeLength": 32, 
        "LineNumberTable": {
          "lineNumberTableLength": 2, 
          "lineNumberTableList": [
            {
              "startPc": 0, 
              "lineNumber": 21
            }, 
            {
              "startPc": 3, 
              "lineNumber": 22
            }
          ]
        }, 
        "LocalVariableTable": {
          "localVariableTableLength": 3, 
          "localVariableTableList": [
            {
              "startPc": 0, 
              "length": 22, 
              "name": "this", 
              "desc": "Lcom/anbai/sec/bytecode/TestHelloWorld;", 
              "index": 0
            }, 
            {
              "startPc": 0, 
              "length": 22, 
              "name": "content", 
              "desc": "Ljava/lang/String;", 
              "index": 1
            }, 
            {
              "startPc": 3, 
              "length": 19, 
              "name": "str", 
              "desc": "Ljava/lang/String;", 
              "index": 2
            }
          ]
        }
      }
    }
  }
}
```

解析`Code`的指令集时需要对照指令集映射表，然后根据不同的指令实现不一样的指令处理逻辑，指令列表和详细的描述请参考：[JVM规范-指令](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-6.html#jvms-6.5)。