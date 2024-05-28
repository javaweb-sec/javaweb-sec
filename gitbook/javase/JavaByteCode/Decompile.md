# Java class反编译

在渗透测试的时候需要审计的代码通常是`class文件`或者`jar包`，在没有源文件的情况下我们可以通过反编译`class/jar`的方式阅读程序逻辑。

Java源码就是未经编译的`.java`文件，我们可以很轻松的阅读其中的代码逻辑，而字节码`.class`文件则是`.java`文件经过编译之后产生的无法直接阅读的二进制文件，不过我们可以通过反编译工具将`class文件`反编译成`java源文件`。我们通常会使用到[JD-GUI](http://jd.benow.ca/)、[Recaf](https://github.com/Col-E/Recaf)、[IDEA Fernflower插件](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine/src/org/jetbrains/java/decompiler)、[Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer/releases)/[Fernflower](https://the.bytecode.club/showthread.php?tid=5)、[JAD](http://www.javadecompilers.com/jad)、[JBE](http://www.cs.ioc.ee/~ando/jbe/)、[Cafebabe](https://github.com/GraxCode/Cafebabe)、[JByteMod](https://github.com/GraxCode/JByteMod-Beta)、[jclasslib](https://github.com/ingokegel/jclasslib)等工具来反编译/分析`class文件`。

当然，反编译工具很多时候也不是万能的，`JD-GUI`经常遇到无法反编译或反编译过程中程序直接崩溃的情况，遇到这类情况我们通常可以使用`IDEA`反编译试试，如果`IDEA`也无法反编译可以使用`JBE`或者`JDK`自带的`javap命令`来读取`class类字节码`，如果连`javap`都无法识别该`class文件`，那么这个类可能存在无法编译问题，也有可能类文件被加密处理过(自定义`ClassLoader`来`loadClass`加密后的类、或者借助`JNI`、`JVMTI`调用动态链接库)。

## javap

`javap`是JDK自带的一个命令行反汇编工具，命令行参数如下：

```bash
用法: javap <options> <classes>
其中, 可能的选项包括:
  -help  --help  -?        输出此用法消息
  -version                 版本信息
  -v  -verbose             输出附加信息
  -l                       输出行号和本地变量表
  -public                  仅显示公共类和成员
  -protected               显示受保护的/公共类和成员
  -package                 显示程序包/受保护的/公共类
                           和成员 (默认)
  -p  -private             显示所有类和成员
  -c                       对代码进行反汇编
  -s                       输出内部类型签名
  -sysinfo                 显示正在处理的类的
                           系统信息 (路径, 大小, 日期, MD5 散列)
  -constants               显示最终常量
  -classpath <path>        指定查找用户类文件的位置
  -cp <path>               指定查找用户类文件的位置
  -bootclasspath <path>    覆盖引导类文件的位置
```

### 查看类字节码

可根据javap命令控制输出信息，如：`javap -c -l TestHelloWorld.class`可显示类方法的字节码信息，如下图：

![image-20201019180336096](https://oss.javasec.org/images/image-20201019180336096.png)

如果想要获取到详细的类信息可使用`-v`参数。



## JD-GUI

`JD-GUI`使用纯Java编写，使用的反编译实现是[jd-core](https://github.com/java-decompiler/jd-core)，支持`JDK 1.1.8 - Java 12`，支持`Lambda表达式`、`方法引用`、`默认方法`等特性，是一款非常简单易用的反编译工具。

![image-20201019111635786](https://oss.javasec.org/images/image-20201019111635786.png)

`JD-GUI`在反编译的时候还会主动关联`Maven`仓库，如果反编译的jar在maven仓库中存在会自动下载类源码，如下图：

![image-20201019111844349](https://oss.javasec.org/images/image-20201019111844349.png)

字符串搜索：

![img](https://oss.javasec.org/images/image-20201019142922249.png)

`JD-GUI`支持批量反编译，在菜单中点击`File`-->`Save All Sources`即可反编译整个jar文件，如下图：

![img](https://oss.javasec.org/images/image-20201019152122562.png)



除此之外，`JD-GUI`还有Eclipse和IDEA的插件：http://java-decompiler.github.io/、https://plugins.jetbrains.com/plugin/7100-java-decompiler-intellij-plugin。

官方网站：http://java-decompiler.github.io/

Github：https://github.com/java-decompiler/jd-gui

反编译jd-core：https://github.com/java-decompiler/jd-core

版本下载：https://github.com/java-decompiler/jd-gui/releases



## Recaf

[Recaf](https://github.com/Col-E/Recaf)是一个使用`JavaFX`开发的现代化反编译工具，它不但具备编译功能，而且还可以直接直接编辑反编译后的类文件、查看字节码、Hex编辑、中文支持等丰富功能。

### 编辑模式

`Recaf`默认使用的是反编译模式，可根据需求选择为Hex或者Table模式，如下图：

![img](https://oss.javasec.org/images/image-20201019140224424.png)

#### 反编译模式

`Recaf`的默认编辑视图是反编译模式，如果使用的是JDK运行的`Recaf`，还可以直接编辑反编译后的class文件，如下图：

![image-20201019113213048](https://oss.javasec.org/images/image-20201019113213048.png)

#### Hex模式编辑

![image-20201019135516449](https://oss.javasec.org/images/image-20201019135516449.png)

#### Table模式/字节码编辑

![img](https://oss.javasec.org/images/image-20201019135811893.png)

字节码编辑：

![img](https://oss.javasec.org/images/image-20201019135923429.png)

### Java Agent/Attach模式

`Recaf`支持`Agent模式`或者`attach模式`（注入）。

#### Agent Attach模式

在菜单栏中点击`注入`菜单，选择`Running process`可以看到本机所有运行的Java进程，如下图：

![img](https://oss.javasec.org/images/image-20201019142224784.png)

`attach`模式可附加`Recaf`到一个指定的JVM进程：

![img](https://oss.javasec.org/images/image-20201019140022294.png)

#### Agent模式

[Agent模式](https://github.com/Col-E/Recaf/issues/31)需要在启动`Recaf`的时候指定`-javaagent:`参数，如下图，以`Agent模式`启动`Recaf`，启动完成后会弹出一个`Recaf Instrumentation`的窗体：

![image-20201019142104679](https://oss.javasec.org/images/image-20201019142104679.png)

### 字符串搜索

`Recaf`支持很多种搜索方式，如下图：

![img](https://oss.javasec.org/images/image-20201019143255436.png)

字符串搜索测试：

![img](https://oss.javasec.org/images/image-20201019143217542.png)



详细文档：https://www.coley.software/Recaf/doc-setup-get.html

Github：https://github.com/Col-E/Recaf

版本下载：https://github.com/Col-E/Recaf/releases



## FernFlower/IDEA

`Fernflower`是一个简单高效的反编译命令行工具，`Fernflower`已成为了`JetBrains`的`intellij-community`内置反编译工具，同时`Fernflower`还有一个非常好用的GUI工具： `Bytecode Viewer`。

**`Fernflower`反编译jar示例：**

`java -jar fernflower.jar jarToDecompile.jar decomp/`

其中`jarToDecompile.jar`是需要反编译的jar文件，`decomp`是反编译后的`class文件`所存放的目录。需要注意的是`Fernflower`如遇无法反编译的情况可能会生成空的java文件！

### 使用Find命令和Fernflower实现批量反编译jar

通常我们在某些特殊的场景下拿到的只是jar文件，那么我们应该如何反编译整个jar包的class文件呢？

`find`命令并不能支持Java反编译，但是`find`命令可以非常方便的搜索经过编译后的二进制文件中的内容，所以有的时候使用`find`命令通常是最简单实用的。例如使用`find`命令搜索某个关键字： `find ./ -type f -name "*.class" |xargs grep XXXX` 。

有的时候我们只有项目war包没有源码，只能在`WEB-INF/lib`中找程序的源码，这个时候我们可以巧妙的使用`find`命令加`Fernflower`来实现反编译所有的jar包。

这里以`jcms`的一个非常老版本为例,`jcms`最终给客户部署的war包中源码并不是在`WEB-INF/classes`目录下，而是将整个`jcms`系统按模块打包成了多个jar包放在了`WEB-INF/lib`目录下。我们可以通过搜索`com.hanweb`包名称来找出所有jar中包含了`jcms`的文件并通过`Fernflower`来反编译。

```bash
java -jar /Users/yz/Desktop/javaweb-decomplier/javaweb-decomplier.jar -dgs=1 $(find /Users/yz/Desktop/jcms/WEB-INF/lib/ -type f -name "*.jar" |xargs grep "com.hanweb" |awk '{print $3}') /Users/yz/jcms-decomplier
```

执行上面的命令后会在`jcms-decomplier`目录下看到所有的jar已经被`Fernflower`反编译了。

![img](https://oss.javasec.org/images/4.2.png)

依赖的jar: [javaweb-decomplier](https://github.com/javaweb-sec/javaweb-decomplier)、[Intellij java-decompiler](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine)。



Github：https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine/src/org/jetbrains/java/decompiler

Fernflower文档：https://the.bytecode.club/fernflower.txt

### IDEA反编译

`IDEA`自带的反编译工具`FernFlower`，在IDEA中可以直接打开class文件，默认将使用`FernFlower`反编译，如下图：

![img](https://oss.javasec.org/images/image-20201019143701601.png)

IDEA支持class文件名(`⇧⌘F`)、类方法名称(`⇧⌘O`)搜索。


## Bytecode Viewer

![img](https://oss.javasec.org/images/image-20201019145310008.png)

`Bytecode Viewer`是一个基于`FernFlower`实现的轻量级，用户友好的Java字节码可视化工具，`Bytecode Viewer`具备了如下强大功能：

1. Java 反编译GUI；
2. `Bytecode`编辑器 GUI；
3. `Smali` GUI ；
4. `Baksmali` GUI；
5. `APK`编辑器 GUI；
6. `Dex`编辑器 GUI；
7. `APK`反编译 GUI；
8. `DEX`反编译 GUI；
9. `Procyon` Java反编译 GUI；
10. `Krakatau` GUI；
11. `CFR` Java反编译 GUI；
12. `FernFlower` Java反编译 GUI；
13. `DEX2Jar` GUI；
14. `Jar2DEX` GUI；
15. `Jar-Jar` GUI；
16. `Hex`视图；
17. 代码搜索；
18. 调试器；

### 多视图

`Bytecode Viewer`提供了多种视图可供选择，在`View`菜单中可选择不同的视图或反编译引擎（默认使用的是反编译和字节码视图），当选择了`Editable`后可编辑反编译后的class文件，如下图：

![image-20201019151037905](https://oss.javasec.org/images/image-20201019151037905.png)

### 代码搜索功能

代码搜索功能支持字符串、正则表达式、调用方法和调用字段搜索，如下图：

![img](https://oss.javasec.org/images/image-20201019154032388.png)

### 反编译安卓APK

![image-20201019151742200](https://oss.javasec.org/images/image-20201019151742200.png)

Github：https://github.com/Konloch/bytecode-viewer

版本下载：https://github.com/Konloch/bytecode-viewer/releases



## JAD

`jad`是一个C++编写的跨平台的Java反编译命令行工具，可使用`jad`命令反编译class文件，`jad`最新版本是发布于2006年的`1.5.8g`，距今，已有14年没更新了。

反编译示例：`jad TestHelloWorld.class`

![img](https://oss.javasec.org/images/image-20201019160840290.png)

`JAD`参数如下：

```bash
Jad accepts the following options:

-a       - annotate the output with JVM bytecodes (default: off)
-af      - same as -a, but output fully qualified names when annotating
-clear   - clear all prefixes, including the default ones (can be abbreviated as -cl)
-b       - output redundant braces (e.g., if(a) { b(); }, default: off)
-d 
 - directory for output files (will be created when necessary)
  -dead    - try to decompile dead parts of code (if any) (default: off)
  -disass  - disassemble method bytecodes (no JAVA source generated)
  -f       - output fully qualified names for classes/fields/methods (default: off)
  -ff      - output class fields before methods (default: after methods)
  -i       - output default initializers for all non-final fields
  -l  - split strings into pieces of maximum  chars (default: off)
  -lnc     - annotate the output with line numbers (default: off)
  -lradix - display long integers using the specified radix (8, 10 or 16)
  -nl      - split strings on newline character (default: off)
  -nocast  - don't generate auxiliary casts
  -nocode  - don't generate the source code for methods
  -noconv  - don't convert Java identifiers (default: convert)
  -noctor  - suppress the empty constructors
  -nodos   - do not check for class files written in DOS mode (CR before NL, default: check)
  -nofd    - don't disambiguate fields with the same names by adding signatures to their names (default: do)
  -noinner - turn off the support of inner classes (default: on)
  -nolvt   - ignore Local Variable Table information
  -nonlb   - don't output a newline before opening brace (default: do)
  -o       - overwrite output files without confirmation (default: off)
  -p       - send decompiled code to STDOUT (e.g., for piping)
  -pi - pack imports into one line after  imports (default: 3)
  -pv - pack fields with identical types into one line (default: off)
  -pa - prefix for all packages in generated source files
  -pc - prefix for classes with numerical names (default: _cls)
  -pf - prefix for fields with numerical names (default: _fld)
  -pe - prefix for unused exception names (default: _ex)
  -pl - prefix for locals with numerical names (default: _lcl)
  -pm - prefix for methods with numerical names (default: _mth)
  -pp - prefix for method parms with numerical names (default: _prm)
  -r       - restore package directory structrure
  -radix - display integers using the specified radix (8, 10 or 16)
  -s  - output file extension (by default '.jad')
  -safe    - generate additional casts to disambiguate methods/fields (default: off)
  -space   - output space between keyword (if/for/while/etc) and expression (default: off)
  -stat    - display the total number of processed classes/methods/fields
  -t       - use tabs instead of spaces for indentation
  -t  - use  spaces for indentation (default: 4)
  -v       - display method names being decompiled
  -8       - convert UNICODE strings into 8-bit strings
  using the current ANSI code page (Win32 only)
  -&       - redirect STDERR to STDOUT (Win32 only)
```

官方网站：http://www.kpdus.com/jad.html#general

版本下载：http://www.javadecompilers.com/jad

## JBE

`JBE(Java Bytecode Editor)`是一个使用[BCEL](http://jakarta.apache.org/bcel/)和[jclasslib bytecode viewer](http://www.ej-technologies.com/products/jclasslib/overview.html)实现的编辑class字节码编辑的工具，`JBE`只能编辑字节码，不能反编译，`JBE`也有近10年未更新了，不支持高版本的Java class解析。

添加常量池对象：

![img](https://oss.javasec.org/images/image-20201019164255758.png)

### 删除常量池对象

![img](https://oss.javasec.org/images/image-20201019164424942.png)

### 删除类成员变量

![img](https://oss.javasec.org/images/image-20201019164800876.png)

### 查看字节码

![img](https://oss.javasec.org/images/image-20201019164619458.png)

### 编辑字节码

![image-20201019163143075](https://oss.javasec.org/images/image-20201019163143075.png)

### 删除类方法

![img](https://oss.javasec.org/images/image-20201019164705299.png)



官方地址：https://set.ee/jbe/

## jclasslib bytecode viewer

`jclasslib`是一个有20年历史的java字节码浏览工具，可以非常方便的查看class的常量池、字节码等信息，非常适合学习解析class字节码。新版本的`jclasslib`支持中文，改用了`Kotlin`编写。

![image-20201019163424897](https://oss.javasec.org/images/image-20201019163424897.png)

Github：https://github.com/ingokegel/jclasslib

版本下载：https://github.com/ingokegel/jclasslib/releases



## Cafebabe Lite

![image-20201019171226961](https://oss.javasec.org/images/image-20201019171226961.png)

`Cafebabe`是一个用户友好的Java字节码编辑器。

### 反编译

![image-20201019170742769](https://oss.javasec.org/images/image-20201019170742769.png)

### 字节码编辑

![image-20201019171439589](https://oss.javasec.org/images/image-20201019171439589.png)

### 字节码可视化

![img](https://oss.javasec.org/images/image-20201019170935681.png)

**Cafebabe / JByteMod / other比较：**


|                                             | reJ       | JBytedit  | JBE       | Recaf     | JByteMod | Cafebabe  |
| ------------------------------------------: | --------- | --------- | --------- | --------- | -------- | --------- |
|                           Edit Instructions | 部分 | 部分 | 部分 | 部分 | Yes      | 部分 |
|                                 Edit Fields | Yes       | Yes       | Yes       | Yes       | Yes      | No        |
|                             Edit Attributes | 部分 | 部分 | 部分 | Yes       | Yes      | No        |
|                       Edit Try Catch Blocks | Yes       | No        | Yes       | Yes       | Yes      | No        |
|                               Decompiler(s) | No        | No        | No        | Yes       | Yes      | Yes       |
|                       Analytical Decompiler | No        | No        | No        | No        | Yes      | Yes       |
|                              Colored Syntax | No        | Yes       | 部分 | Yes       | Yes      | Yes       |
|                                      Labels | Yes       | Yes       | No        | Yes       | Yes      | Yes       |
|                        Multilingual support | No        | No        | No        | Yes       | Yes      | Yes       |
|                                  LDC Search | 部分 | Yes       | No        | Yes       | Yes      | No        |
|                          Instruction Search | 部分 | No        | No        | Yes       | Yes      | No        |
|                                Regex Search | No        | No        | No        | Yes       | Yes      | No        |
|                                Class Search | No        | No        | No        | Yes       | No       | No        |
|                            In-Editor Search | No        | No        | No        | No        | Yes      | No        |
|                              In-Editor Help | Yes       | No        | No        | unknown   | Yes      | Yes       |
|                          Frame Regeneration | No        | No        | No        | Yes       | Yes      | Yes       |
| Automatic Frame Regeneration (no libraries) | No        | No        | No        | No        | No       | Yes       |
|                          Control Flow Graph | No        | No        | No        | No        | Yes      | Yes       |
|                              Java 8 Support | No        | 部分 | No        | No        | Yes      | Yes       |
|                             Java 11 Support | No        | No        | No        | Yes       | Yes      | Yes       |
|                             Java 12 Support | No        | No        | No        | Yes       | Yes      | Yes       |
|                        Obfuscation Analysis | No        | No        | No        | No        | Yes      | No        |
|                      Live Code Manipulation | No        | No        | No        | Yes       | Yes      | No        |

Github：https://github.com/GraxCode/Cafebabe/

版本下载：https://github.com/GraxCode/Cafebabe/releases



## JByteMod

`JByteMod`和`Cafebabe`都是同一个作者开发的，`JByteMod`在`Cafebabe`基础上做了非常多的改进，支持反编译、字节码编辑、可视化分析、Agent注入等。

### 反编译

![img](https://oss.javasec.org/images/image-20201019173646644.png)

### 字节码编辑

![img](https://oss.javasec.org/images/image-20201019173107619.png)

### 字节码分析

![img](https://oss.javasec.org/images/image-20201019174255460.png)

### 方法信息编辑

![img](https://oss.javasec.org/images/image-20201019173815788.png)

### 方法添加/编辑

![img](https://oss.javasec.org/images/image-20201019173247265.png)



Github：https://github.com/GraxCode/JByteMod-Beta

版本下载：https://github.com/GraxCode/JByteMod-Beta/releases