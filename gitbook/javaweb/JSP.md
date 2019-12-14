# JSP基础

`JSP`(`JavaServer Pages`) 是与 `PHP`、`ASP`、`ASP.NET` 等类似的脚本语言，`JSP`是为了简化`Servlet`的处理流程而出现的替代品，早期的`Java EE`因为只能使用`Servlet`来处理客户端请求而显得非常的繁琐和不便，使用JSP可以快速的完成后端逻辑请求。

正因为在`JSP`中可以直接调用Java代码来实现后端逻辑的这一特性，黑客通常会编写带有恶意攻击的JSP文件(俗称`WebShell`)来实现对服务器资源的恶意请求和控制。

现代的MVC框架(如：`Spring MVC 5.x`)已经完全抛弃了`JSP`技术，采用了`模板引擎(如：Freemark)`或者`RESTful`的方式来实现与客户端的交互工作,或许某一天`JSP`技术也将会随着产品研发的迭代而彻底消失。

## JSP 三大指令

1. `<%@ page ... %>`   定义网页依赖属性，比如脚本语言、error页面、缓存需求等等

2. `<%@ include ... %>`  包含其他文件（静态包含）

3. `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>` 引入标签库的定义

## JSP 表达式(EL)

`EL表达式`(`Expression Language`)语言,常用于在jsp页面中获取请求中的值，如获取在Servlet中设置的`Attribute`:`${名称}`。使用EL表达式可以实现命令执行，我们将会在后续EL表达式章节中详细讲解。

## JSP 标准标签库(JSTL)

JSP标准标签库（JSTL）是一个JSP标签集合，它封装了JSP应用的通用核心功能。

JSTL支持通用的、结构化的任务，比如迭代，条件判断，XML文档操作，国际化标签，SQL标签。 除了这些，它还提供了一个框架来使用集成JSTL的自定义标签。

## JSP 九大对象

从本质上说 JSP 就是一个Servlet，JSP 引擎在调用 JSP 对应的 jspServlet 时，会传递或创建 9 个与 web 开发相关的对象供 jspServlet 使用。 JSP 技术的设计者为便于开发人员在编写 JSP 页面时获得这些 web 对象的引用，特意定义了 9 个相应的变量，开发人员在JSP页面中通过这些变量就可以快速获得这 9 大对象的引用。

如下：

| 变量名      | 类型                | 作用                                        |
| ----------- | ------------------- | ------------------------------------------- |
| pageContext | PageContext         | 当前页面共享数据，还可以获取其他8个内置对象 |
| request     | HttpServletRequest  | 客户端请求对象，包含了所有客户端请求信息    |
| session     | HttpSession         | 请求会话                                    |
| application | ServletContext      | 全局对象，所有用户间共享数据                |
| response    | HttpServletResponse | 响应对象，主要用于服务器端设置响应信息      |
| page        | Object              | 当前Servlet对象,`this`                      |
| out         | JspWriter           | 输出对象，数据输出到页面上                  |
| config      | ServletConfig       | Servlet的配置对象                           |
| exception   | Throwable           | 异常对象                                    |