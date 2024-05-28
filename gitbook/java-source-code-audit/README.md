# Java 代码审计

通俗的说Java代码审计就是通过审计Java代码来发现Java应用程序自身中存在的安全问题，由于Java本身是编译型语言，所以即便只有class文件的情况下我们依然可以对Java代码进行审计。对于未编译的Java源代码文件我们可以直接阅读其源码，而对于已编译的class或者jar文件我们就需要进行反编译了。

Java代码审计其本身并无多大难度，只要熟练掌握审计流程和常见的漏洞审计技巧就可比较轻松的完成代码审计工作了。但是Java代码审计的方式绝不仅仅是使用某款审计工具扫描一下整个Java项目代码就可以完事了，一些业务逻辑和程序架构复杂的系统代码审计就非常需要审计者掌握一定的Java基础并具有具有一定的审计经验、技巧甚至是对Java架构有较深入的理解和实践才能更加深入的发现安全问题。

本章节讲述Java代码审计需要掌握的前置知识以及Java代码审计的流程、技巧。

## 准备环境和辅助工具

在开始Java代码审计前请自行安装好Java开发环境，建议使用MacOS、Ubuntu操作系统。

所谓“工欲善其事，必先利其器”，合理的使用一些辅助工具可以极大的提供我们的代码审计的效率和质量！

强烈推荐下列辅助工具：

| 类型         | 名称                                                         |
| ------------ | ------------------------------------------------------------ |
| IDE          | [Jetbrains IDEA](https://www.jetbrains.com/idea/)、[Eclipse](https://www.eclipse.org/)、[NetBeans](https://netbeans.org/) |
| 编辑器       | [Visual Studio Code](https://code.visualstudio.com/)、[Sublime text](http://www.sublimetext.com/3) |
| 反编译工具   | [JD-GUI](http://jd.benow.ca/)、[Recaf](https://github.com/Col-E/Recaf)、[IDEA Fernflower](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine/src/org/jetbrains/java/decompiler)、[Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer/releases)/[Fernflower](https://the.bytecode.club/showthread.php?tid=5)、[JAD](http://www.javadecompilers.com/jad)、[JBE](http://www.cs.ioc.ee/~ando/jbe/)、[Cafebabe](https://github.com/GraxCode/Cafebabe)、[JByteMod](https://github.com/GraxCode/JByteMod-Beta) |
| 商业审计工具 | [Fortify](https://www.microfocus.com/zh-cn/products/static-code-analysis-sast/overview)、[CodePecker](http://www.codepecker.com.cn/Analyse) |

![img](https://oss.javasec.org/images/code-tools.png)

`IntelliJ IDEA`是`Jetbrains`出品的一款非常强大的`Java IDE`，IDEA提供了强大的代码搜索、反编译、动态调试等功能可以最大程度的辅助我们代码审计。