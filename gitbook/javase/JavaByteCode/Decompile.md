# Java class反编译

在渗透测试的时候需要审计的代码通常是`class文件`或者`jar包`，在没有源文件的情况下我们可以通过反编译`class/jar`的方式阅读程序逻辑。

Java源码就是未经编译的`.java`文件，我们可以很轻松的阅读其中的代码逻辑，而字节码`.class`文件则是`.java`文件经过编译之后产生的无法直接阅读的二进制文件，不过我们可以通过反编译工具将`class文件`反编译成`java源文件`。我们通常会使用到[JD-GUI](http://jd.benow.ca/)、[Recaf](https://github.com/Col-E/Recaf)、[IDEA Fernflower插件](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine/src/org/jetbrains/java/decompiler)、[Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer/releases)/[Fernflower](https://the.bytecode.club/showthread.php?tid=5)、[JAD](http://www.javadecompilers.com/jad)、[JBE](http://www.cs.ioc.ee/~ando/jbe/)、[Cafebabe](https://github.com/GraxCode/Cafebabe)、[JByteMod](https://github.com/GraxCode/JByteMod-Beta)等工具来反编译`class文件`。

当然，反编译工具很多时候也不是万能的，`JD-GUI`经常遇到无法反编译或反编译过程中程序直接崩溃的情况，遇到这类情况我们通常可以使用`IDEA`反编译试试，如果`IDEA`也无法反编译可以使用`JBE`或者`JDK`自带的`javap命令`来读取`class类字节码`，如果连`javap`都无法识别该`class文件`，那么这个类必然存在无法编译问题，也有可能类文件被加密处理过(自定义`ClassLoader`来`loadClass`加密后的类、或者借助`JVMTI`调用动态链接库)。

## JD-GUI

`JD-GUI`是一个非常常用的反编译工具，它可以直接

## 反编译整个Jar技巧

### Fernflower

Fernflower可以很轻松的实现jar的完整反编译，执行如下命令即可： `java -jar fernflower.jar jarToDecompile.jar decomp/` 其中`jarToDecompile.jar`是需要反编译的jar文件，`decomp`是反编译后的`class文件`所存放的目录。需要注意的是`Fernflower`如遇无法反编译的情况可能会生成空的java文件！

### JD-GUI

`JD-GUI`是一个带GUI的反编译工具，在`JD-GUI`的菜单中点击`File`-->`Save All Sources`即可反编译jar。

### IDEA

IDEA默认就支持jar包反编译，同时还支持class文件名(`⇧⌘F`)、类方法名称(`⇧⌘O`)搜索。

### Bytecode-Viewer

`FernFlower`提供了GUI版本[Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer/releases),`Bytecode-Viewer`提供了直接反编译的`class`、`jar`、`zip`、`apk`、`dex`功能，直接拖拽jar就可以直接对整个jar进行反编译了。

![4.1](../../images/4.1.png)

### 使用Find命令和Fernflower实现批量反编译jar

通常我们在某些特殊的场景下拿到的只是jar文件，那么我们应该如何反编译整个jar包的class文件呢？

`find`命令并不能支持Java反编译，但是`find`命令可以非常方便的搜索经过编译后的二进制文件中的内容，所以有的时候使用`find`命令通常是最简单实用的。例如使用`find`命令搜索某个关键字： `find ./ -type f -name "*.class" |xargs grep XXXX` 。

有的时候我们只有项目war包没有源码，只能在`WEB-INF/lib`中找程序的源码，这个时候我们可以巧妙的使用`find`命令加`Fernflower`来实现反编译所有的jar包。

这里以`jcms`的一个非常老版本为例,`jcms`最终给客户部署的war包中源码并不是在`WEB-INF/classes`目录下，而是将整个`jcms`系统按模块打包成了多个jar包放在了`WEB-INF/lib`目录下。我们可以通过搜索`com.hanweb`包名称来找出所有jar中包含了`jcms`的文件并通过`Fernflower`来反编译。

```bash
java -jar /Users/yz/Desktop/javaweb-decomplier/javaweb-decomplier.jar -dgs=1 $(find /Users/yz/Desktop/jcms/WEB-INF/lib/ -type f -name "*.jar" |xargs grep "com.hanweb" |awk '{print $3}') /Users/yz/jcms-decomplier
```

执行上面的命令后会在`jcms-decomplier`目录下看到所有的jar已经被`Fernflower`反编译了。

![4.2](../../images/4.2.png)

依赖的jar: [javaweb-decomplier](https://github.com/anbai-inc/javaweb-decomplier)、[Intellij java-decompiler](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine)。
