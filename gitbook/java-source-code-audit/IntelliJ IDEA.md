# IntelliJ IDEA技巧

## 1. IDEA搜索技巧

IDEA的搜索快捷键是:`⇧⌘F`,使用IDEA提供的搜索功能可以非常快速的定位漏洞点信息。

![img](https://oss.javasec.org/images/5.png)

IDEA可以通过自定义搜索范围来精确查找我们需要审计的代码。默认搜索的是所有的位置，不过我们可以点击红色箭头指向的`...`按钮来细化我们的搜索范围。

### 1.1 自定义范围搜索

![img](https://oss.javasec.org/images/6.png)

**自定义搜索范围示例:**

![img](https://oss.javasec.org/images/7.png)

自定义搜索范围后就可以在搜索时使用自定义的配置进行范围搜索了，有助于我们在挖漏洞的时候缩小代码定位范围。

![img](https://oss.javasec.org/images/8.png)

### 1.2. 标记搜索

搜索快捷键: `⌘O`，标记搜索支持`类名`、`方法名`搜索（`包括class或jar文件`中的方法也支持搜索）。

![img](https://oss.javasec.org/images/9.png)

## 2. Java调用链搜索

当我们审计代码的时候发现某个方法或类有漏洞时我们需要定位到漏洞的请求地址(触发点)，复杂业务系统往往会让我们很难定位到漏洞的触发点。借助IDEA的方法调用链搜索功能就可以很轻松的找出方法的调用链和触发点。

选择`类或者方法名`-->`右键`-->`Find Useages`或者使用快捷键`⌥F7`

![10](https://oss.javasec.org/images/10.png)

## 3. 显示类所有方法

如果某个类有非常多的方法，我们无法快速找到想看的方法时可以使用快捷键`⌘F12`

![img](https://oss.javasec.org/images/image-20200919224838936.png)

如果想显示父类方法可以把`Inherited members`勾上，反之去掉。

## 4. 显示类继承关系

某些类实现的非常复杂，继承和实现了非常多的类，比较影响我们分析业务，这个时候我们可以在某个类的空白处`右键`->`Diagrams`->`Show Diagram`或者使用快捷键`⌥⇧⌘U`

![img](https://oss.javasec.org/images/image-20200919225146232.png)

示例`RequestFacade`类的继承关系图：

![img](https://oss.javasec.org/images/image-20200919225952115.png)

点击左上角的小图标`F`、`M❤`、`M`、`P`、`I`分别会展示详细的：`成员变量`、`构造方法`、`方法`、`属性`、`内部类`。

如果想显示多个类的继承关系，可以将任意类文件拖拽到右图就会生成多类之间的继承关系，如`Tomcat`中的`HttpServletRequest`类和`ApplicationHttpRequest`类都实现了`HttpServletRequest`接口，那么拖拽到一起就可以看到它们俩之间的如下关联关系：

![image-20200919230639828](https://oss.javasec.org/images/image-20200919230639828.png)

## 5. 自动反编译

IDEA的反编译效果非常的不错，大部分时间都可以直接使用IDEA的反编译功能来代替反编译工具。

### 5.1 自动反编译class文件

将任意的`class`文件丢到`IDEA`的源码目录就可以立即看到反编译之后的文件，这样就可以省去打开反编译工具的时间了，如图：

![img](https://oss.javasec.org/images/image-20200919231402589.png)

请注意，直接在`IDEA`中粘贴是会出错的，应该以文件的形式拷贝到对应目录。如果嫌打开目录IDEA中的文件所在目录过于麻烦，可以点击文件名或在已打开的文件中`右键`->`Reveal in Finder`

![img](https://oss.javasec.org/images/image-20200919231943616.png)

如果不想鼠标点击可以设置个自己喜欢的快捷键，这样就会非常方便了：

![img](https://oss.javasec.org/images/image-20200919232114213.png)

### 5.2 jar文件反编译

`IDEA`反编译`jar`文件也是非常的方便，只需把`jar`包丢到任意目录，然后`右键`->`Add as library`就可以了。

![img](https://oss.javasec.org/images/image-20200919232616338.png)

`jar`反编译示例：

![img](https://oss.javasec.org/images/image-20200919232814807.png)

## 6. Http请求测试

很多人为了测试API接口总喜欢使用`Burp`或者`Postman`之类的工具去发送`Http`请求，殊不知`IDEA`就内置了非常方便的`Http`请求工具。在项目的任意位置：`右键`->`new`->`File`->`test.http`，然后就会创建出一个叫`test.http`的文件。

![img](https://oss.javasec.org/images/image-20200920010627753.png)

`Http`环境变量配置文件不是必须的，如需配置，需点击右上角的`Add Environment File`，然后自行添加变量，如：

```json
{
  "dev": {
    "url": "http://localhost:8080",
    "json": "application/json"
  }
}
```

## 7. 本地历史记录

在调试IDEA的时候如果不小心误删了文件或者改某个文件时都改一半了发现改错了，而且还没有`git`之类的版本提交记录。这个时候我们可以使用IDEA的本地文件历史编辑记录功能，选择任意文件或者目录`右键`->`Local History`->`Show History`：

![img](https://oss.javasec.org/images/image-20200920121916759.png)

查看本地修改文件记录：

![img](https://oss.javasec.org/images/image-20200920122518373.png)

也可直接选择时间点，点击`Revert`还原文件到指定时间修改的版本：

![img](https://oss.javasec.org/images/image-20200920122644169.png)

## 8. 文件比较

`IDEA`不仅可以很方便的比较`版本控制`中的修改文件，还自带了一个文件比较功能。

### 8.1 粘贴板文件比较

复制一个文件的内容到粘贴板，然后打开需要比较的文件后点击`右键`->`Compare with Clipboard`：

![img](https://oss.javasec.org/images/image-20200920123854460.png)

文件对比：

![img](https://oss.javasec.org/images/image-20200920124128916.png)

### 8.2 文件比较

如果嫌比较粘贴板比较麻烦，可以直接选中需要比较的文件`右键`->`Compare With...`，如下：

![img](https://oss.javasec.org/images/image-20200920124401867.png)

然后在本地文件中选择一个需要比较的文件即可：

![image-20200920124623020](https://oss.javasec.org/images/image-20200920124623020.png)

### 8.3 VCS文件比较

`版本控制`的文件比较方式非常简单，配置好`VCS(Version Vontrol System，版本控制系统)`后本地修改的文件和远程的文件可以直接比较，如图：

![img](https://oss.javasec.org/images/image-20200920161539727.png)

## 9. 类/资源文件热更新

`IDEA`中默认不会将修改的文件和资源自动同步到`Web Server`或者`SpringBoot`，需要我们手动设置当类文件或资源文件发生修改后同步更新。

`Web容器`热更新：

![img](https://oss.javasec.org/images/image-20200922204404489.png)

`SpringBoot`热更新:

![img](https://oss.javasec.org/images/image-20200922204435421.png)