### JSP基础

JSP 是与 PHP、ASP、ASP.NET 等语言类似的脚本语言，是为了简化Servlet的工作出现的替代品，早期只有servlet，只能使用response输出标签数据，非常麻烦。

**JSP 三大指令**

1. `<%@ page ... %>`   定义网页依赖属性，比如脚本语言、error页面、缓存需求等等

2. `<%@ include ... %>`  包含其他文件（静态包含）

3. `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>` 引入标签库的定义

**JSP 表达式(EL)**

Expression Language 表达式语言,常用于**取值**，我们之前在JSP中写java代码必须写在`<%   %>`里面。并且取值代码比较繁琐，而EL表达式可以使我们的取值代码更加简洁。

语法非常简单：`${}`

**JSP 三种注释**

1. HTML 注释：`<!--html注释，且客户端可见-->`；
2. JSP 注释：`<%--JSP注释，客户端不可见--%>`；
3. JSP 脚本注释：即 Java 注释 `//单行 , /*多行 */`。

**JSP 标准标签库(JSTL)**

JSP标准标签库（JSTL）是一个JSP标签集合，它封装了JSP应用的通用核心功能。

JSTL支持通用的、结构化的任务，比如迭代，条件判断，XML文档操作，国际化标签，SQL标签。 除了这些，它还提供了一个框架来使用集成JSTL的自定义标签。

根据JSTL标签所提供的功能，可以将其分为5个类别。

- 核心标签
- 格式化标签
- SQL 标签
- XML 标签
- JSTL 函数

**JSP 九大对象**

从本质上说 JSP 就是一个Servlet，<font color='blue'>JSP 引擎在调用 JSP 对应的 jspServlet 时，会传递或创建 9 个与 web 开发相关的对象供 jspServlet 使用</font>。 JSP 技术的设计者为便于开发人员在编写 JSP 页面时获得这些 web 对象的引用，特意定义了 9 个相应的变量，开发人员在JSP页面中通过这些变量就可以快速获得这 9 大对象的引用。

如下：

| 变量名      | 真实类型            | 作用                                        |
| ----------- | ------------------- | ------------------------------------------- |
| pageContext | PageContext         | 当前页面共享数据，还可以获取其他8个内置对象 |
| request     | HttpServletRequest  | 一次请求访问的多个资源(转发)                |
| session     | HttpSession         | 一次会话的多个请求间                        |
| application | ServletContext      | 所有用户间共享数据                          |
| response    | HttpServletResponse | 响应对象                                    |
| page        | Object              | 当前页面(Servlet)的对象  this               |
| out         | JspWriter           | 输出对象，数据输出到页面上                  |
| config      | ServletConfig       | Servlet的配置对象                           |
| exception   | Throwable           | 异常对象                                    |