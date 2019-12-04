# Java IO/NIO多种读写文件方式

上一章节我们提到了Java 对文件的读写分为了基于阻塞模式的IO和非阻塞模式的NIO，本章节我将列举一些我们常用于读写文件的方式。

我们通常读写文件都是使用的阻塞模式，与之对应的也就是`java.io.FileSystem`。`java.io.FileInputStream`类提供了对文件的读取功能，Java的其他读取文件的方法基本上都是封装了`java.io.FileInputStream`类，比如：`java.io.FileReader`。

## FileInputStream

**使用FileInputStream实现文件读取Demo:**

```java
package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileInputStreamDemo {

	public static void main(String[] args) throws IOException {
		File file = new File("/etc/passwd");

		// 打开文件对象并创建文件输入流
		FileInputStream fis = new FileInputStream(file);

		// 定义每次输入流读取到的字节数对象
		int a = 0;

		// 定义缓冲区大小
		byte[] bytes = new byte[1024];

		// 创建二进制输出流对象
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// 循环读取文件内容
		while ((a = fis.read(bytes)) != -1) {
			// 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
			// 下标0开始截取，a表示输入流read到的字节数。
			out.write(bytes, 0, a);
		}

		System.out.println(out.toString());
	}

}
```

输出结果如下:

```xml
##
# User Database
# 
# Note that this file is consulted directly only when the system is running
# in single-user mode.  At other times this information is provided by
# Open Directory.
#
# See the opendirectoryd(8) man page for additional information about
# Open Directory.
##
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
daemon:*:1:1:System Services:/var/root:/usr/bin/false
.....内容过长省去多余内容
```

调用链如下：

```java
java.io.FileInputStream.readBytes(FileInputStream.java:219)
java.io.FileInputStream.read(FileInputStream.java:233)
com.anbai.sec.filesystem.FileInputStreamDemo.main(FileInputStreamDemo.java:27)
```

其中的readBytes是native方法，文件的打开、关闭等方法也都是native方法：

```java
private native int readBytes(byte b[], int off, int len) throws IOException;
private native void open0(String name) throws FileNotFoundException;
private native int read0() throws IOException;
private native long skip0(long n) throws IOException;
private native int available0() throws IOException;
private native void close0() throws IOException;
```

`java.io.FileInputStream`类对应的native实现如下：

```c
JNIEXPORT void JNICALL
Java_java_io_FileInputStream_open0(JNIEnv *env, jobject this, jstring path) {
    fileOpen(env, this, path, fis_fd, O_RDONLY);
}

JNIEXPORT jint JNICALL
Java_java_io_FileInputStream_read0(JNIEnv *env, jobject this) {
    return readSingle(env, this, fis_fd);
}

JNIEXPORT jint JNICALL
Java_java_io_FileInputStream_readBytes(JNIEnv *env, jobject this,
        jbyteArray bytes, jint off, jint len) {
    return readBytes(env, this, bytes, off, len, fis_fd);
}

JNIEXPORT jlong JNICALL
Java_java_io_FileInputStream_skip0(JNIEnv *env, jobject this, jlong toSkip) {
    jlong cur = jlong_zero;
    jlong end = jlong_zero;
    FD fd = GET_FD(this, fis_fd);
    if (fd == -1) {
        JNU_ThrowIOException (env, "Stream Closed");
        return 0;
    }
    if ((cur = IO_Lseek(fd, (jlong)0, (jint)SEEK_CUR)) == -1) {
        JNU_ThrowIOExceptionWithLastError(env, "Seek error");
    } else if ((end = IO_Lseek(fd, toSkip, (jint)SEEK_CUR)) == -1) {
        JNU_ThrowIOExceptionWithLastError(env, "Seek error");
    }
    return (end - cur);
}

JNIEXPORT jint JNICALL
Java_java_io_FileInputStream_available0(JNIEnv *env, jobject this) {
    jlong ret;
    FD fd = GET_FD(this, fis_fd);
    if (fd == -1) {
        JNU_ThrowIOException (env, "Stream Closed");
        return 0;
    }
    if (IO_Available(fd, &ret)) {
        if (ret > INT_MAX) {
            ret = (jlong) INT_MAX;
        } else if (ret < 0) {
            ret = 0;
        }
        return jlong_to_jint(ret);
    }
    JNU_ThrowIOExceptionWithLastError(env, NULL);
    return 0;
}
```

完整代码参考OpenJDK:[openjdk/src/java.base/share/native/libjava/FileInputStream.c](https://github.com/unofficial-openjdk/openjdk/blob/531ef5d0ede6d733b00c9bc1b6b3c14a0b2b3e81/src/java.base/share/native/libjava/FileInputStream.c)



## FileOutputStream

使用FileOutputStream实现写文件Demo:

```java
package com.anbai.sec.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileOutputStreamDemo {

	public static void main(String[] args) throws IOException {
		// 定义写入文件路径
		File file = new File("/tmp/1.txt");

		// 定义待写入文件内容
		String content = "Hello World.";

		// 创建FileOutputStream对象
		FileOutputStream fos = new FileOutputStream(file);

		// 写入内容二进制到文件
		fos.write(content.getBytes());
		fos.flush();
		fos.close();
	}

}
```

代码逻辑比较简单: 打开文件->写内容->关闭文件，调用链和底层实现分析请参考`FileInputStream`。



## RandomAccessFile

Java提供了一个非常有趣的读取文件内容的类: `java.io.RandomAccessFile`,这个类名字面意思是任意文件内容访问，特别之处是这个类不仅可以像`java.io.FileInputStream`一样读取文件，而且还可以写文件。

RandomAccessFile读取文件测试代码:

```java
package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class RandomAccessFileDemo {

	public static void main(String[] args) {
		File file = new File("/etc/passwd");

		try {
			// 创建RandomAccessFile对象,r表示以只读模式打开文件，一共有:r(只读)、rw(读写)、
			// rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
			RandomAccessFile raf = new RandomAccessFile(file, "r");

			// 定义每次输入流读取到的字节数对象
			int a = 0;

			// 定义缓冲区大小
			byte[] bytes = new byte[1024];

			// 创建二进制输出流对象
			ByteArrayOutputStream out = new ByteArrayOutputStream();

			// 循环读取文件内容
			while ((a = raf.read(bytes)) != -1) {
				// 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
				// 下标0开始截取，a表示输入流read到的字节数。
				out.write(bytes, 0, a);
			}

			System.out.println(out.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
```

任意文件读取特性体现在如下方法：

```java
// 获取文件描述符
public final FileDescriptor getFD() throws IOException 

// 获取文件指针
public native long getFilePointer() throws IOException;
 
// 设置文件偏移量
private native void seek0(long pos) throws IOException;
```

`java.io.RandomAccessFile`类中提供了几十个`readXXX`方法用以读取文件系统，最终都会调用到`read0`或者`readBytes`方法，我们只需要掌握如何利用`RandomAccessFile`读/写文件就行了。

**RandomAccessFile写文件测试代码:**

```java
package com.anbai.sec.filesystem;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class RandomAccessWriteFileDemo {

	public static void main(String[] args) {
		File file = new File("/tmp/test.txt");

		// 定义待写入文件内容
		String content = "Hello World.";

		try {
			// 创建RandomAccessFile对象,rw表示以读写模式打开文件，一共有:r(只读)、rw(读写)、
			// rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
			RandomAccessFile raf = new RandomAccessFile(file, "rw");

			// 写入内容二进制到文件
			raf.write(content.getBytes());
			raf.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
```



## FileSystemProvider

前面章节提到了JDK7新增的NIO.2的`java.nio.file.spi.FileSystemProvider`,利用`FileSystemProvider`我们可以利用支持异步的通道(`Channel`)模式读取文件内容。

**FileSystemProvider读取文件内容示例:**

```java
package com.anbai.sec.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FilesDemo {

	public static void main(String[] args) {
		// 通过File对象定义读取的文件路径
//		File file  = new File("/etc/passwd");
//		Path path1 = file.toPath();

		// 定义读取的文件路径
		Path path = Paths.get("/etc/passwd");

		try {
			byte[] bytes = Files.readAllBytes(path);
			System.out.println(new String(bytes));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
```

`java.nio.file.Files`是JDK7开始提供的一个对文件读写取非常便捷的API，其底层实在是调用了`java.nio.file.spi.FileSystemProvider`来实现对文件的读写的。最为底层的实现类是`sun.nio.ch.FileDispatcherImpl#read0`。

基于NIO的文件读取逻辑是：打开FileChannel->读取Channel内容。

打开FileChannel的调用链为：

```java
sun.nio.ch.FileChannelImpl.<init>(FileChannelImpl.java:89)
sun.nio.ch.FileChannelImpl.open(FileChannelImpl.java:105)
sun.nio.fs.UnixChannelFactory.newFileChannel(UnixChannelFactory.java:137)
sun.nio.fs.UnixChannelFactory.newFileChannel(UnixChannelFactory.java:148)
sun.nio.fs.UnixFileSystemProvider.newByteChannel(UnixFileSystemProvider.java:212)
java.nio.file.Files.newByteChannel(Files.java:361)
java.nio.file.Files.newByteChannel(Files.java:407)
java.nio.file.Files.readAllBytes(Files.java:3152)
com.anbai.sec.filesystem.FilesDemo.main(FilesDemo.java:23)
```

文件读取的调用链为：

```java
sun.nio.ch.FileChannelImpl.read(FileChannelImpl.java:147)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:65)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:109)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:103)
java.nio.file.Files.read(Files.java:3105)
java.nio.file.Files.readAllBytes(Files.java:3158)
com.anbai.sec.filesystem.FilesDemo.main(FilesDemo.java:23)
```



**FileSystemProvider写文件示例:**

```java
package com.anbai.sec.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FilesWriteDemo {

	public static void main(String[] args) {
		// 通过File对象定义读取的文件路径
//		File file  = new File("/etc/passwd");
//		Path path1 = file.toPath();

		// 定义读取的文件路径
		Path path = Paths.get("/tmp/test.txt");

		// 定义待写入文件内容
		String content = "Hello World.";

		try {
			// 写入内容二进制到文件
			Files.write(path, content.getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
```



## 文件读写总结

Java内置的文件读取方式大概就是这三种方式，其他的文件读取API可以说都是对这几种方式的封装而已(依赖数据库、命令执行、自写JNI接口不算，本人个人理解,如有其他途径还请告知)。本章我们通过深入基于IO和NIO的Java文件系统底层API，希望大家能够通过以上Demo深入了解到文件读写的原理和本质。