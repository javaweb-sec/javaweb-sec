# CVE-2020-17510

## 漏洞信息

| 漏洞信息  | 详情                                                                                                                                                      |
|:------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| 漏洞编号  | [CVE-2020-17510](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17510) /  [CNVD-2020-60318](https://www.cnvd.org.cn/flaw/show/CNVD-2020-60318) |
| 影响版本  | shiro  < 1.7.0                                                                                                                                          |
| 漏洞描述  | Apache Shiro 由于处理身份验证请求时存在权限绕过漏洞，远程攻击者可以发送特制的<br>HTTP请求，绕过身份验证过程并获得对应用程序的未授权访问。                                                                         |
| 漏洞关键字 | Spring & 编码 & %2e & 绕过 & /%2e%2e/                                                                                                                       |
| 漏洞补丁  | [Commit-6acaaee](https://github.com/apache/shiro/commit/6acaaee9bb3a27927b599c37fabaeb7dd6109403)                                                       |
| 相关链接  | [https://lists.apache.org/thread/12bn9ysx6ogm830stywro4pkoq8dxzfk](https://lists.apache.org/thread/12bn9ysx6ogm830stywro4pkoq8dxzfk)                    |

## 漏洞详解

本漏洞还是对 AntPathMatcher 的继续绕过。之前已经尝试了 `;` 的 URL 编码，`/` 的双重 URL 编码的绕过，都是因为 Shiro 先 url 解码再标准化和处理的逻辑与 Spring 不同导致的。

那还有什么字符的 URL 编码可能导致问题呢？常见的 URL 中还有什么字符能用呢？答案就是 `.`，`.` 的 URL 编码为 `%2e`。

当一个 `%2e` 出现在请求中时，会发生什么事呢？很显然，shiro 会将其当做 `.` 处理，而 Spring 会将其当做字符 `%2e` 处理。 

此时如果 `%2e` 出现的位置正确，就可以在 shiro 处理后消失，造成差异，例如访问："/audit/%2e/"：
- Shiro url decode："/audit/./"
- Shiro 标准化路径："/audit/"
- Spring 标准化路径："/audit/%2e/"
- Spring url decode："/audit/."

由此可见，Shiro 匹配的路径和 Spring 匹配的路径相差了一个字符 "."，将造成绕过。此时依旧借助单个 "*" 的通配符以及 `PathVariable` 注解 String 类型的参数的场景触发漏洞。

![](https://oss.javasec.org/images/1643104107679.png)


可以使用的 payload 包括：
- `/%2e`
- `/%2e/`
- `/%2e%2e`
- `/%2e%2e/`

因为上面的写法都会被 shiro 的标准化路径处理掉，并且同时能被 `PathVariable` 注解 String 类型的参数匹配到。

## 漏洞修复

Shiro 在 [Commit-6acaaee](https://github.com/apache/shiro/commit/6acaaee9bb3a27927b599c37fabaeb7dd6109403) 中提交了本次漏洞的修复。

在本次修复中可以看到，Shiro 的思路再次转变，不再按照 Spring 和 Tomcat 改自己的处理代码，也不再给自己加代码来适配 Spring，而是创建了 UrlPathHelper 的子类 ShiroUrlPathHelper，并重写了 `getPathWithinApplication` 和 `getPathWithinServletMapping` 两个方法，全部使用 Shiro 自己的逻辑 `WebUtils#getPathWithinApplication` 进行返回。 

![](https://oss.javasec.org/images/1643097638169.png)

在之前的分析中我们知道，Spring 与 Shiro 处理逻辑之间的差异就在这个位置，而现在 Shiro 直接把代码逻辑重写，通过注入自己的代码来修改 Spring 的相关逻辑，用来保证二者没有差异。究竟是怎么注入的呢？在配置类中 import 了 `ShiroRequestMappingConfig` 类。

![](https://oss.javasec.org/images/1643097999114.png)

`ShiroRequestMappingConfig` 类会向 `RequestMappingHandlerMapping#urlPathHelper` 设置为 `ShiroUrlPathHelper`。

![](https://oss.javasec.org/images/1643098610269.png)

设置后，Spring 匹配 handler 时获取路径的逻辑就会使用 Shiro 提供的逻辑，保持了二者逻辑的一致。从而避免了绕过的情况。

### 注意

这里需要注意的是，Shiro 官方对这个漏洞的修复非常坑，根据官方给出的[信息](https://lists.apache.org/thread/12bn9ysx6ogm830stywro4pkoq8dxzfk)，Shiro 将修复放在了 `shiro-spring-boot-web-starter` 包中，也就是使用了 `shiro-spring-boot-web-starter` 进行配置的项目，升级版本才会使防御代码生效，才会注入 ShiroUrlPathHelper 。

如果你没有使用`shiro-spring-boot-web-starter` 自动配置，而是引入 `shiro-spring` 自己进行注入 Bean，单纯的升级版本是无法防御本次 CVE 的，需要：
1. 根据[这个链接](https://github.com/apache/shiro/blob/shiro-root-1.7.0/support/spring/src/main/java/org/apache/shiro/spring/web/config/ShiroRequestMappingConfig.java#L28-L30)中的代码来进行手动配置；
2. 或根据[这个链接](https://shiro.apache.org/spring-framework.html#SpringFramework-WebConfig)将 `ShiroRequestMappingConfig` 添加在 auto configuration 配置中。

如果不配置，将无法有效防御此 CVE。

### 绕过

这个修复在当时来看，如果配置正确，防御能力是 OK 的，整个思路都没问题，但是随着 Spring 自身代码的迭代，却又将安全问题暴露了出来。在高版本的 Spring 中，由于 `alwaysUseFullPath` 默认为 true ，导致应用程序使用 `UrlPathHelper.defaultInstance` 来处理，而不是 Shiro 实现的 `ShiroUrlPathHelper` 来处理。

![](https://oss.javasec.org/images/1643096936792.png)

这样就导致这个修复补丁又被完美的绕过了。

![](https://oss.javasec.org/images/1643097189106.png)


# CVE-2020-17523

## 漏洞信息

| 漏洞信息  | 详情                                                                                                                                                                                     |
|:------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 漏洞编号  | [CVE-2020-17523](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17523) /  [CNVD-2021-09492](https://www.cnvd.org.cn/flaw/show/CNVD-2021-09492)                                |
| 影响版本  | shiro  < 1.7.1                                                                                                                                                                         |
| 漏洞描述  | Apache Shiro 由于处理身份验证请求时存在权限绕过漏洞，远程攻击者可以发送特制的<br>HTTP请求，绕过身份验证过程并获得对应用程序的未授权访问。                                                                                                        |
| 漏洞关键字 | Spring & trim & %20 & 绕过 & /%20%20/                                                                                                                                                    |
| 漏洞补丁  | [Commit-ab1ea4a](https://github.com/apache/shiro/commit/ab1ea4a2006f6bd6a2b5f72740b7135662f8f160)                                                                                      |
| 相关链接  | [https://www.anquanke.com/post/id/230935](https://www.anquanke.com/post/id/230935) <br> [https://www.eso.org/~ndelmott/url_encode.html](https://www.eso.org/~ndelmott/url_encode.html) |


## 漏洞详解

继续绕过...

在使用 `.` 、`/` 、`;` 的 URL 编码绕过之后，这次使用的是空格的 URL 编码：`%20`。

之前讲过，在匹配访问路径与配置鉴权路径时，在 `AntPathMatcher#doMatch` 方法中，首先会调用 `org.apache.shiro.util.StringUtils#tokenizeToStringArray` 方法将 pattern 以及 path 处理成 String 数组，再进行比对。

![](https://oss.javasec.org/images/1643108121514.png)

这个方法会继续调用有四个参数的重写方法，并且后两个参数的值均为 true。其实这部分也是抄的 spring 的代码。

![](https://oss.javasec.org/images/1643108220835.png)

可以看到后两个布尔类型参数的意义是对 StringTokenizer 结果的处理的标志 flag，代表是否对 token 进行 trim 操作，以及是否忽略空的 token。

![](https://oss.javasec.org/images/1643108468671.png)

因此，在被 `WebUtils#getPathWithinApplication`  方法处理过的 URI，再与配置路径匹配时，又会处理空格。

![](https://oss.javasec.org/images/1643108941676.png)

因此对于 "/audit/%20" 这种访问，可以理解为会被 shiro 处理成 "/audit/" 这种格式去匹配。

而 Spring 的处理逻辑，在配置了 CVE-2020-17510 的安全补丁后，虽然与 shiro 保持了一致，但是在匹配 handler 时并没有空格的处理，因此可以继续以字符串的方式匹配。

依旧是依赖单个 "*" 的通配符以及 `PathVariable` 注解 String 类型的参数的场景触发漏洞。复现如下，`%20` 随便加。 

![](https://oss.javasec.org/images/1643109660920.png)

由于之前的安全修复，URL 中的非 ASCII 字符会被 filter 干掉，因此，我 FUZZ 了
 %00-ff  的全部字符，发现只有 %20 能用。
![](https://oss.javasec.org/images/1643167384780.png)


## 漏洞修复

Shiro 在  [Commit-ab1ea4a](https://github.com/apache/shiro/commit/ab1ea4a2006f6bd6a2b5f72740b7135662f8f160) 中提交了本次漏洞的修复。

可以看到是指定了 `StringUtils#tokenizeToStringArray` 方法的第三个参数 trimTokens 为 false，也就是说不再去除空格，从而消除了本次漏洞的影响。

![](https://oss.javasec.org/images/1643108044903.png)

其实即使不报安全漏洞， shiro 也应该修复这个逻辑，因为 spring 本身可以支持以空格作为 RequestMapping。

![](https://oss.javasec.org/images/1643111008009.png)

而 shiro 对其处理逻辑则有问题，配置后访问将不生效。

![](https://oss.javasec.org/images/1643111002243.png)

如下：

![](https://oss.javasec.org/images/1643110977704.png)


# CVE-2021-41303

## 漏洞信息

| 漏洞信息  | 详情                                                                                                                                                                                                                      |
|:------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 漏洞编号  | [CVE-2021-41303](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41303) / [SHIRO-825](https://issues.apache.org/jira/browse/SHIRO-825)                                                                          |
| 影响版本  | shiro  < 1.8.0                                                                                                                                                                                                          |
| 漏洞描述  | Apache Shiro 与 Spring Boot 一起使用时，远程攻击者可以发送特制的 HTTP 请求，<br>绕过身份验证过程并获得对应用程序的未授权访问。                                                                                                                                       |
| 漏洞关键字 | Spring & 回退 & /aaa/*/ & 绕过                                                                                                                                                                                              |
| 漏洞补丁  | [Commit-4a20bf0](https://github.com/apache/shiro/commit/4a20bf0e995909d8fda58f9c0485ea9eb2d43f0e)                                                                                                                       |
| 相关链接  | [https://threedr3am.github.io/](https://threedr3am.github.io/2021/09/22/%E4%BB%8E%E6%BA%90%E7%A0%81diff%E5%88%86%E6%9E%90Apache-Shiro%201.7.1%E7%89%88%E6%9C%AC%E7%9A%84auth%20bypass%EF%BC%88CVE-2021-41303%EF%BC%89/) |


## 漏洞详解

在上一个版本的更新中，除了安全修复，还更新了几个逻辑，来优化对路径末尾 "/" 的情况的处理。

第一是匹配路径的方法 `PathMatchingFilter#pathsMatch`，在曾经 SHIRO-682 的更新中针对这个方法进行了修改，为了兼容 Spring 对访问路径最后一个 "/" 的支持。

![](https://oss.javasec.org/images/1643172673662.png)

在本次版本更新中，添加了一层判断逻辑，即先使用原始请求判断，如果没有匹配成功，再使用去掉 "/" 的路径尝试匹配。

第二是在 `PathMatchingFilterChainResolver` 中新增了一个 `removeTrailingSlash` 方法，用来去除请求路径中的最后的 "/"。

![](https://oss.javasec.org/images/1643174895873.png)

并在 `getChain` 方法中更改逻辑，依旧是先使用原来的请求匹配，匹配不到再使用去除请求路径之后的 "/" 来匹配。 

![](https://oss.javasec.org/images/1643174983680.png)

原本的逻辑是，拿到 URI ，直接判断最后是不是 “/”，如果是直接去掉，然后匹配和处理，但改过之后，直接拿过来匹配，如果没匹配到，再尝试去掉 “/” 在匹配，这种情况下，对于带 “/” 的请求将会匹配两次。

不但逻辑复杂了，而且还写出了 BUG。在 else 语句块中，没有将 pathPattern 给到 `filterChainManager#proxy` 方法，反而是将用户可控的 requestURINoTrailingSlash 给了进去。

这为什么会产生漏洞呢？这一切先从一个 BUG 说起：SHIRO-825。首先来复现一下这个 ISSUES ，我们配置如下，同样是使用单个 "*" 匹配:

```java
chainDefinition.addPathDefinition("/audit/list", "authc");
chainDefinition.addPathDefinition("/audit/*", "anon");
```

可以看到，`/audit/` 路径下只有 list 是需要鉴权的，其他不需要。Controller 代码如下：

```java
@Controller
@RequestMapping(value = "/audit")
public class AuditController {


	@GetMapping(value = "/list")
	public void list(HttpServletResponse response) throws IOException {
		response.getWriter().println("you have to be auditor to view this page");
	}


	@GetMapping(value = "/{name}")
	public void list(@PathVariable String name, HttpServletResponse response) throws IOException {
		response.getWriter().println("no need auth to see this page:" + name);
	}
}
```

此时访问 "/audit/aaa" 正常：

![](https://oss.javasec.org/images/1643179339365.png)

但是访问 "/audit/aaa/" 报错：

![](https://oss.javasec.org/images/1643179406759.png)

原因就是，shiro 会用处理过的用户请求路径去配置文件里找对应的路径，自然找不到就抛异常的。

![](https://oss.javasec.org/images/1643179722258.png)

那这个 BUG 是如何延伸成为漏洞的呢？不难想到，如果 shiro 在配置文件中找到了这个路径，那逻辑就正常了。我们再来配置一下场景，现在改为如下配置：

```java
chainDefinition.addPathDefinition("/audit/*", "authc");
chainDefinition.addPathDefinition("/audit/list", "anon");
```

现在的逻辑是，配置了 `/audit/*` 需要认证，而 `/audit/list` 不需要认证，注意配置的顺序，正常逻辑下，对于 `/audit/list` 对应的路径，是需要鉴权的，因为他会被 `/audit/*` 匹配到，但是 `/audit/*` 不能匹配 `/audit/list/`，会去掉 "/" 进行匹配，能匹配到，且在后续的逻辑中也可以找到对应的路径，就可以绕过鉴权。

![](https://oss.javasec.org/images/1643181257015.png)


## 漏洞修复

Shiro 在 [Commit-4a20bf0](https://github.com/apache/shiro/commit/4a20bf0e995909d8fda58f9c0485ea9eb2d43f0e)  中修复了此问题。可以看到修改后正确的传入了 pathPattern。

![](https://oss.javasec.org/images/1643176045349.png)


## 思考

本漏洞的分析是参考了 threedr3am 师傅的博客，但存在几个疑问：
- 本 CVE 在 CVSS 3.0 获得了 9.8 的评分，CVSS 2.0 获得了 7.5 的评分，但上面的漏洞场景似乎限制很大，给不到高危。
- ISSUES 的报送者是报送 BUG，并非安全风险，而官方的通告又致谢了另外一个安全从业者。
- 我翻了所有的更新代码，确实没找到其他类似漏洞修复的地方，因为 shiro 一般修绕过的时候都会给出新的 testcase，确实没找到别的。

