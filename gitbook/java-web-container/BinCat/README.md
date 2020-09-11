# BinCat

大家好，我是`BinCat`，一个基于`JavaEE API`实现的超简单(不安全的非标准的​​，仅用于学习Java容器原理)的`Web Server`。

![temp_paste_image_060b117e682e40715171017c22358241](../../images/temp_paste_image_060b117e682e40715171017c22358241.png)

## Http请求协议解析

Http协议(`超文本传输协议，HyperText Transfer Protocol`)是一种用于分布式、协作式和超媒体信息系统的应用层协议。HTTP是万维网的数据通信的基础。要想能够处理Http请求就必须先解析Http请求，不同的Http请求方式对应的数据包也是不一样的。

**GET请求包示例：**

```
GET / HTTP/1.1
Host: localhost:8080
User-Agent: curl/7.64.1
Accept: */*

```

**POST请求包示例：**

```
POST /?s=java HTTP/1.1
Host: localhost:8080
User-Agent: curl/7.64.1
Accept: */*
Cookie: Hm_lvt_f4c571d9b8811113b4f18e87a6dbe619=1597582351; Hm_lpvt_f4c571d9b889b22224f18e87a6dbe619=1599562693; JSESSIONID=LgxJ127kT7ymIGbC2T1TeipnMP9_2_CqJQjmrqOb
Content-Length: 17
Content-Type: application/x-www-form-urlencoded

id=123&name=admin
```

### 解析Http简要流程

解析POST请求的简单流程如下(`非multipart或chunked请求`)：

1. 解析第一行的Http协议信息。
2. 解析Http请求Header信息。
3. 解析请求主体(Body)部分。

### 解析Http请求协议信息

接下来我们将以上述的POST包解析为例简单的实现Http协议解析。如上POST包，第一行数据中包含了请求方式、请求的URL地址以及Http协议版本信息(空格隔开)：`POST /?s=java HTTP/1.1`。那么我们只需要使用空白符号将字符串切割成数组即可完成解析。

**解析Http请求协议示例代码片段：**

```java
// 从Socket中读取一行数据，读取请求的URL
String str = dis.readLine();

// 切割请求Http协议信息
String[] strs = str.split("\\s+");

// 解析Http请求方法类型
String method = strs[0];

// 解析Http请求URL地址
String url = strs[1];

// 解析Http请求版本信息
String httpVersion = strs[2];
```

### 解析Http请求Header信息

解析完Http请求协议后就应该继续解析Http Header信息了，Http请求头从第二行开始到一个空白行结束，Header中的键值对以`: `分割，如下：

```
Host: localhost:8080
User-Agent: curl/7.64.1
Accept: */*
Content-Length: 17
Content-Type: application/x-www-form-urlencoded
```

**解析Http头示例代码片段：**

```java
// 创建Header对象
Map<String, String> header = new ConcurrentHashMap<String, String>();

// 解析请求头信息
while (true) {
    // 按行读取Header头信息
    String line = dis.readLine();

    // 当读取到空行时停止解析Header
    if ("".equals(line)) {
      	break;
    }

    // 切割Header的Key/Value
    String[] headers = line.split(":\\s*", -1);

    header.put(headers[0], headers[1]);
}
```

解析完Header后剩下的也就是最后的Http请求主体部分了，浏览器会将请求的参数以`&`为连接符拼接出多个参数，参数名称和参数值以`=`分割，并且参数值默认会使用URL编码，如下:

```
id=123&name=admin
```

解析body中的请求参数时需要先从Header中读取请求的主体大小，即:`Content-Length`，因为body中允许出现换行`\n`等特殊内容，所以解析body时应该按字节读取数据。除此之外，解析Body中的请求参数之前应该先解析URL中的请求参数，即GET传参部分：`/?s=java`，然后再解析body中的参数。

**解析Http GET参数代码片段：**

```java
// 解析GET请求参数
if (url.contains("?")) {
	String[] parameterStrs = url.split("\\?");
	this.requestURL = parameterStrs[0];

	// 初始化Http请求的QueryString
	this.queryString = parameterStrs[1];

	// 按"&"切割GET请求的参数
	String[] parameters = queryString.split("&");

	// 解析GET请求参数
	for (String parameter : parameters) {
		String[] tmp = parameter.split("=", -1);

		if (tmp.length == 2) {
			parameterMap.put(tmp[0], new String[]{URLDecoder.decode(tmp[1])});
		}
	}
}
```

**Cookie解析**

Cookie是非常Http请求中非常重要的用户凭证，Cookie位于请求头中的`cookie`字段，多个`Cookie`以`; `分割，`Cookie`的参数和参数值以`=`切分。`Cookie`中会存储一个叫`JSESSIONID`(Java标准容器中叫`JSESSIONID`)，用于识别服务器端存储的用户会话信息。

**示例Cookie：**

```
Cookie: Hm_lvt_f4c571d9b8811113b4f18e87a6dbe619=1597582351; Hm_lpvt_f4c571d9b889b22224f18e87a6dbe619=1599562693; JSESSIONID=LgxJ127kT7ymIGbC2T1TeipnMP9_2_CqJQjmrqOb
```

**示例Cookie解析代码片段：**

```java
// 解析Cookie
if (headerMap.containsKey("cookie")) {
	// 切分Cookie字符串
	String[] cookies = headerMap.get("cookie").split(";\\s+", -1);

	// 初始化Cookie数组长度
	this.cookie = new Cookie[cookies.length];

	for (int i = 0; i < cookies.length; i++) {
		String   cookieStr = cookies[i];
		String[] tmp       = cookieStr.split("=", -1);

		if (tmp.length == 2) {
			// 创建Cookie对象
			this.cookie[i] = new Cookie(tmp[0], URLDecoder.decode(tmp[1]));
		}
	}
}
```



### 解析Http请求主体

**解析Http主体代码片段：**

```java
if ("POST".equalsIgnoreCase(method)) {
	String contentType = header.get("Content-Type");

	// 解析POST请求参数
	if ("application/x-www-form-urlencoded".equalsIgnoreCase(contentType)) {
		// 获取请求的主体长度
		int contentLength = Integer.parseInt(header.get("Content-Length"));

		// 创建一个和请求体一样大小的缓冲区
		byte[] bytes = new byte[contentLength];

		// 读取POST主体内容
		dis.read(bytes);

		// 解析POST请求内容
		String body = new String(bytes, "ISO8859-1");

		// 按"&"切割POST请求的参数
		String[] parameters = body.split("&");

		// 解析POST请求参数
		for (String parameter : parameters) {
			String[] tmp = parameter.split("=", -1);

			if (tmp.length == 2) {
				parameterMap.put(tmp[0], URLDecoder.decode(tmp[1]));
			}
		}
	}
}
```

