# Java class文件解析

为了能够更加深入的学习class结构，本章节将写一个[ClassByteCodeParser类](https://github.com/anbai-inc/javaweb-sec/blob/master/javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/ClassByteCodeParser.java)来实现简单的class文件解析。

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



## 常量池解析

解析常量池信息时需要先解析出常量池对象的数量，然后遍历常量池，解析`cp_info`对象。

```
u2 constant_pool_count;
cp_info constant_pool[constant_pool_count-1];
```

解析片段：

```java
// u2 constant_pool_count;
this.poolCount = dis.readUnsignedShort();

// cp_info constant_pool[constant_pool_count-1];
for (int i = 1; i <= poolCount - 1; i++) {
   int tag = dis.readUnsignedByte();
}
```





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

`readAttributes`方法这里先不做