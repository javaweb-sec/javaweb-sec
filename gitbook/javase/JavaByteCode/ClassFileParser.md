# Java class文件解析

为了能够更加深入的学习class结构，本章节将写一个[ClassByteCodeParser类](https://github.com/javaweb-sec/javaweb-sec/blob/master/javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/ClassByteCodeParser.java)（有极小部分数据结构较复杂没解析）来实现简单的class文件解析。

首先我们创建一个用于测试的`TestHelloWorld.java`文件，源码如下：

```java
package com.anbai.sec.bytecode;

import java.io.Serializable;

/**
 * Creator: yz
 * Date: 2019/12/17
 */
@Deprecated
public class TestHelloWorld implements Serializable {

	private static final long serialVersionUID = -7366591802115333975L;

	private long id = 1l;

	private String username;

	private String password;

	public String hello(String content) {
		String str = "Hello:";
		return str + content;
	}

	public static void main(String[] args) {
		TestHelloWorld test = new TestHelloWorld();
		String         str  = test.hello("Hello World~");

		System.out.println(str);
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String toString() {
		return "TestHelloWorld{" +
				"id=" + id +
				", username='" + username + '\'' +
				", password='" + password + '\'' +
				'}';
	}

}
```

然后使用`javac`将`TestHelloWorld.java`编译成`TestHelloWorld.class`文件，或者使用maven构建`javaweb-sec/javaweb-sec-source/javase/`项目，构建成功后在`javaweb-sec/javaweb-sec-source/javase/target/classes/com/anbai/sec/bytecode/`目录下可以找到`TestHelloWorld.class`文件。

最后编写一个`ClassByteCodeParser类`，严格按照JVM规范中的类文件格式文档规定，依次解析class文件的各种数据类型就可以实现字节码解析了。

**ClassByteCodeParser代码片段（省略了getter/setter和解析逻辑）：**

```java
package com.anbai.sec.bytecode;

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
	 * 解析Class字节码
	 *
	 * @param in 类字节码输入流
	 * @throws IOException 解析IO异常
	 */
	private void parseByteCode(InputStream in) throws IOException {
    // 将输入流转换成DataInputStream
    this.dis = new DataInputStream(in);
    
    // 解析字节码逻辑代码
  }

	public static void main(String[] args) throws IOException {
		// 解析单个class文件
		File                classFile  = new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/target/classes/com/anbai/sec/bytecode/TestHelloWorld.class");
		ClassByteCodeParser codeParser = new ClassByteCodeParser();

		codeParser.parseByteCode(new FileInputStream(classFile));
		System.out.println(JSON.toJSONString(codeParser));
	}

}
```

解析完`TestHelloWorld.class`后将会生成一个json字符串，省略掉复杂的`constantPoolMap`、`fieldList`、`methodList`、`attributes`属性后格式如下：

```json
{
    "accessFlags": 33, 
    "attributes": {}, 
    "attributesCount": 3, 
    "constantPoolMap": {}, 
    "fieldList": [], 
    "fieldsCount": 4, 
    "interfaces": [
        "java/io/Serializable"
    ], 
    "interfacesCount": 1, 
    "magic": -889275714, 
    "major": 51, 
    "methodList": [], 
    "methodsCount": 10, 
    "minor": 0, 
    "poolCount": 95, 
    "superClass": "java/lang/Object", 
    "thisClass": "com/anbai/sec/bytecode/TestHelloWorld"
}
```



## 魔数/版本解析

一个合法的class文件以固定的`0xCAFEBABE`格式开始，所以需要先读取4个字节，判断文件二进制格式是否是合法。

```
u4 magic;
u2 minor_version;
u2 major_version;
```

**魔数和版本号解析代码片段：**

```java
// u4 magic;
int magic = dis.readInt();

// 校验文件魔数
if (0xCAFEBABE == magic) {
   this.magic = magic;

   // u2 minor_version
   this.minor = dis.readUnsignedShort();

   // u2 major_version;
   this.major = dis.readUnsignedShort();
}
```

解析结果：

```json
{
    "magic": -889275714, 
    "minor": 0, 
    "major": 51
}
```

其中`"major": 51`对应的JDK版本是JDK1.7。

## 常量池解析

解析常量池信息时需要先解析出常量池对象的数量，然后遍历常量池，解析`cp_info`对象。

```
u2 constant_pool_count;
cp_info constant_pool[constant_pool_count-1];
```

为了便于理解解析过程，特意将常量池解析流程单独拆开成如下几步：

1. 读取常量池数量（`u2 constant_pool_count;`）；
2. 读取`tag`；
3. 根据不同的`tag`类型解析常量池对象；
4. 解析常量池中的对象；
5. 链接常量池中的索引引用；

**常量池解析片段：**

```java
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
        //			cp_info {
        //				u1 tag;
        //				u1 info[];
        //			}
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
```

**解析常量池对象代码片段：**

```java
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
          //					CONSTANT_Utf8_info {
          //						u1 tag;
          //						u2 length;
          //						u1 bytes[length];
          //					}

          int length = dis.readUnsignedShort();
          byte[] bytes = new byte[length];
          dis.read(bytes);

          map.put("tag", CONSTANT_UTF8);
          map.put("value", new String(bytes, UTF_8));
          break;
        case CONSTANT_INTEGER:
          //					CONSTANT_Integer_info {
          //						u1 tag;
          //						u4 bytes;
          //					}

          map.put("tag", CONSTANT_INTEGER);
          map.put("value", dis.readInt());
          break;
        case CONSTANT_FLOAT:
          //					CONSTANT_Float_info {
          //						u1 tag;
          //						u4 bytes;
          //					}

          map.put("tag", CONSTANT_FLOAT);
          map.put("value", dis.readFloat());
          break;
        case CONSTANT_LONG:
          //					CONSTANT_Long_info {
          //						u1 tag;
          //						u4 high_bytes;
          //						u4 low_bytes;
          //					}

          map.put("tag", CONSTANT_LONG);
          map.put("value", dis.readLong());
          break;
        case CONSTANT_DOUBLE:
          //					CONSTANT_Double_info {
          //						u1 tag;
          //						u4 high_bytes;
          //						u4 low_bytes;
          //					}

          map.put("tag", CONSTANT_DOUBLE);
          map.put("value", dis.readDouble());
          break;
        case CONSTANT_CLASS:
          //					CONSTANT_Class_info {
          //						u1 tag;
          //						u2 name_index;
          //					}

          map.put("tag", CONSTANT_CLASS);
          map.put("nameIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_STRING:
          //					CONSTANT_String_info {
          //						u1 tag;
          //						u2 string_index;
          //					}

          map.put("tag", CONSTANT_STRING);
          map.put("stringIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_FIELD_REF:
          //					CONSTANT_Fieldref_info {
          //						u1 tag;
          //						u2 class_index;
          //						u2 name_and_type_index;
          //					}

          map.put("tag", CONSTANT_FIELD_REF);
          map.put("classIndex", dis.readUnsignedShort());
          map.put("nameAndTypeIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_METHOD_REF:
          //					CONSTANT_Methodref_info {
          //						u1 tag;
          //						u2 class_index;
          //						u2 name_and_type_index;
          //					}

          map.put("tag", CONSTANT_METHOD_REF);
          map.put("classIndex", dis.readUnsignedShort());
          map.put("nameAndTypeIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_INTERFACE_METHOD_REF:
          //					CONSTANT_InterfaceMethodref_info {
          //						u1 tag;
          //						u2 class_index;
          //						u2 name_and_type_index;
          //					}

          map.put("tag", CONSTANT_INTERFACE_METHOD_REF);
          map.put("classIndex", dis.readUnsignedShort());
          map.put("nameAndTypeIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_NAME_AND_TYPE:
          //					CONSTANT_NameAndType_info {
          //						u1 tag;
          //						u2 name_index;
          //						u2 descriptor_index;
          //					}

          map.put("tag", CONSTANT_NAME_AND_TYPE);
          map.put("nameIndex", dis.readUnsignedShort());
          map.put("descriptorIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_METHOD_HANDLE:
          //					CONSTANT_MethodHandle_info {
          //						u1 tag;
          //						u1 reference_kind;
          //						u2 reference_index;
          //					}

          map.put("tag", CONSTANT_METHOD_HANDLE);
          map.put("referenceKind", dis.readUnsignedByte());
          map.put("referenceIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_METHOD_TYPE:
          //					CONSTANT_MethodType_info {
          //						u1 tag;
          //						u2 descriptor_index;
          //					}

          map.put("tag", CONSTANT_METHOD_TYPE);
          map.put("descriptorIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_DYNAMIC:
          //					CONSTANT_Dynamic_info {
          //						u1 tag;
          //						u2 bootstrap_method_attr_index;
          //						u2 name_and_type_index;
          //					}

          map.put("tag", CONSTANT_DYNAMIC);
          map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
          map.put("nameAndTypeIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_INVOKE_DYNAMIC:
          //					CONSTANT_InvokeDynamic_info {
          //						u1 tag;
          //						u2 bootstrap_method_attr_index;
          //						u2 name_and_type_index;
          //					}

          map.put("tag", CONSTANT_INVOKE_DYNAMIC);
          map.put("bootstrapMethodAttrIdx", dis.readUnsignedShort());
          map.put("nameAndTypeIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_MODULE:
          //					CONSTANT_Module_info {
          //						u1 tag;
          //						u2 name_index;
          //					}

          map.put("tag", CONSTANT_MODULE);
          map.put("nameIndex", dis.readUnsignedShort());
          break;
        case CONSTANT_PACKAGE:
          //					CONSTANT_Package_info {
          //						u1 tag;
          //						u2 name_index;
          //					}

          map.put("tag", CONSTANT_PACKAGE);
          map.put("nameIndex", dis.readUnsignedShort());
          break;
    }

    constantPoolMap.put(index, map);
}
```

解析完常量池的对象后会发现很多数据结构中都引用了其他对象，比如ID（索引位置）为1的常量池对象`CONSTANT_METHOD_REF`引用了ID为21的`CONSTANT_CLASS`对象和ID为64的`CONSTANT_NAME_AND_TYPE`对象，而`CONSTANT_CLASS`对象又引用了`CONSTANT_UTF8`（`java/lang/Object`）、`CONSTANT_NAME_AND_TYPE`同时引用了`CONSTANT_UTF8`（`<init>`）和`CONSTANT_UTF8`（`()V`）,为了能够直观的看到常量池ID为1的对象信息我们就必须要将所有使用索引方式链接的映射关系改成直接字符串引用，最终得到如下结果：

```json
{
    "constantPoolMap": {
        "1": {
            "tag": "CONSTANT_METHOD_REF", 
            "classIndex": 21, 
            "nameAndTypeIndex": 64, 
            "classValue": "java/lang/Object", 
            "nameAndTypeValue": "<init>"
        }
     		.... 省略其他对象
    }
}
```

**常量池对象链接代码片段：**

```java
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
```

为了方便通过ID（常量池索引）访问常量池中的对象值，封装了一个`getConstantPoolValue`方法：

```java
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
```



## 访问标志解析

```java
// u2 access_flags;
this.accessFlags = dis.readUnsignedShort();
```

解析结果：`"accessFlags": 33,`。

## 当前类名称解析

解析类名称的时候直接读取2个无符号数，获取到类名所在的常量池中的索引位置，然后根据常量池ID读取常量池中的字符串内容即可解析出类名。

```java
// u2 this_class;
this.thisClass = (String) getConstantPoolValue(dis.readUnsignedShort());
```

解析结果：`"thisClass": "com/anbai/sec/bytecode/TestHelloWorld"`。

## 当前类的父类名称解析

解析`super_class`的时候也是需要特别注意，当解析`java.lang.Object`时`super_class`的值为0，常量池中不包含索引为0的对象，所以需要直接将父类名称设置为`java/lang/Object`。

```java
// u2 super_class;
int superClassIndex = dis.readUnsignedShort();

// 当解析Object类的时候super_class为0
if (superClassIndex != 0) {
   this.superClass = (String) getConstantPoolValue(superClassIndex);
} else {
   this.superClass = "java/lang/Object";
}
```

解析结果：`"superClass": "java/lang/Object",`。

## 接口解析

解析接口信息时需要先解析出接口的数量，然后就可以遍历出所有的接口名称索引值了。

```
u2 interfaces_count;
u2 interfaces[interfaces_count];
```

**接口解析代码片段：**

```java
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
```

解析结果：

```json
{
    "interfacesCount": 1, 
    "interfaces": [
        "java/io/Serializable"
    ]
}
```

## 成员变量/成员方法解析

成员变量和成员方法的数据结构是一样的，所以可以使用相同的解析逻辑。首先解析出变量/方法的总数量，然后遍历并解析`field_info`或`method_info`对象的所有信息。

**成员变量/成员方法解析代码片段：**

```java
// u2 fields_count;
this.fieldsCount = dis.readUnsignedShort();

// field_info fields[fields_count];
for (int i = 0; i < this.fieldsCount; i++) {
    //				field_info {
    //					u2 access_flags;
    //					u2 name_index;
    //					u2 descriptor_index;
    //					u2 attributes_count;
    //					attribute_info attributes[attributes_count];
    //				}

    this.fieldList.add(readFieldOrMethod());
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
```

成员变量解析结果：

```json
{
    "fieldsCount": 4, 
    "fieldList": [
        {
            "access": 2, 
            "name": "password", 
            "desc": "Ljava/lang/String;", 
            "attributesCount": 0, 
            "attributes": { }
        }, 
        {
            "access": 2, 
            "name": "id", 
            "desc": "J", 
            "attributesCount": 0, 
            "attributes": { }
        }, 
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
        }, 
        {
            "access": 2, 
            "name": "username", 
            "desc": "Ljava/lang/String;", 
            "attributesCount": 0, 
            "attributes": { }
        }
    ]
}
```

成员方法解析结果（因结果过大，仅保留了一个`getPassword`方法）：

```json
{
    "methodsCount": 10, 
    "methodList": [
        {
            "access": 1, 
            "name": "getPassword", 
            "desc": "()Ljava/lang/String;", 
            "attributesCount": 1, 
            "attributes": {
                "attributeName": "Code", 
                "attributeLength": 47, 
                "Code": {
                    "maxStack": 1, 
                    "maxLocals": 1, 
                    "codeLength": 5, 
                    "opcodes": [
                        "aload_0", 
                        "getfield #15 <com/anbai/sec/bytecode/TestHelloWorld.password>", 
                        "areturn"
                    ], 
                    "exceptionTable": {
                        "exceptionTableLength": 0, 
                        "exceptionTableList": [ ]
                    }, 
                    "attributeLength": 47, 
                    "attributes": {
                        "attributeName": "LocalVariableTable", 
                        "attributeLength": 12, 
                        "LineNumberTable": {
                            "lineNumberTableLength": 1, 
                            "lineNumberTableList": [
                                {
                                    "startPc": 0, 
                                    "lineNumber": 49
                                }
                            ]
                        }, 
                        "LocalVariableTable": {
                            "localVariableTableLength": 1, 
                            "localVariableTableList": [
                                {
                                    "startPc": 0, 
                                    "length": 5, 
                                    "name": "this", 
                                    "desc": "Lcom/anbai/sec/bytecode/TestHelloWorld;", 
                                    "index": 0
                                }
                            ]
                        }
                    }
                }
            }
        }
    ]
}
```



## 属性解析

成员变量、成员方法、类对象这三种数据结构都需要解析属性信息，因为逻辑非常复杂，将在下一小节详解。

