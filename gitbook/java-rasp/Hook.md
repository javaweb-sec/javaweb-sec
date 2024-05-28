# RASP Hook机制

Hook机制类似于AOP机制（`Aspect Oriented Programming`，面向切面编程），使用基于Java Agent实现的Hook技术，RASP可以实现对Java类方法执行执行前后插入自定义逻辑，从而实现控制原本的程序执行的业务逻辑。



## ProcessBuilder Hook示例

`java.lang.ProcessBuilder`常用于执行本地系统命令，为了便于理解Hook机制，这里以Hook ProcessBuilder类的start方法作为示例，演示如何Hook机制的工作原理。

**示例 - 未经Hook的原始java.lang.ProcessBuilder类代码片段：**

```java
package java.lang;

import java.io.IOException;
import java.util.List;

public final class ProcessBuilder {

    private List<String> command;

    // 省略其他不相关类和成员变量

    public Process start() throws IOException {
        // 省去其他无关代码
        return ProcessImpl.start(command, environment, dir, redirects, redirectErrorStream);
    }

}
```

ProcessBuilder类可以调用UNIXProcess/ProcessImpl类的native方法执行本地系统命令，默认情况下可以被任意的Java类调用，所以存在安全问题。RASP使用Agent机制动态修改了ProcessBuilder类的start方法字节码，在方法体的前后插入RASP防御代码，当start方法被调用时因为程序逻辑已被RASP更改，必须先执行RASP的防御逻辑之后才能够执行start方法的原始业务逻辑，如果RASP调用内部的检测逻辑后发现可能存在恶意攻击，RASP会终止start方法执行逻辑，从而避免了恶意攻击。

**示例 - RASP的Hook逻辑代码片段：**

```java
package org.javaweb.rasp.agent;

import org.javaweb.rasp.agent.commons.RASPLogger;
import org.javaweb.rasp.agent.hooks.advice.RASPMethodAdvice;
import org.javaweb.rasp.agent.hooks.annotation.RASPClassHook;
import org.javaweb.rasp.agent.hooks.annotation.RASPMethodHook;
import org.javaweb.rasp.agent.utils.ClassUtils;
import org.javaweb.rasp.loader.hooks.RASPHookResult;

/**
 * Hook 本地命令执行
 */
@RASPClassHook
public class LocalCommandHook {

     /**
      * Hook 通用的ProcessBuilder类
      */
     @RASPMethodHook(className = "java.lang.ProcessBuilder", methodName = "start")
     public static class ProcessBuilderHook extends RASPMethodAdvice {

       @Override
       public RASPHookResult<?> onMethodEnter() {
           Object obj = getThisObject();

           try {
               // 获取ProcessBuilder类的command变量值
               List<String> command = ClassUtils.getFieldValue(obj, "command");

               // 将执行的系统命令转换成字符串数组
               String[] commands = command.toArray(new String[command.size()]);

               // 调用processCommand方法，检测执行的本地命令合法性
               return LocalCommandHookHandler.processCommand(commands, obj, this);
           } catch (Exception e) {
           		RASPLogger.log(AGENT_NAME + "获取ProcessBuilder类command变量异常:" + e, e);
           }

         	return new RASPHookResult(RETURN);
       }

     }

     // 省略其他本地命令执行Hook点
  
}
```

**示例 - 经过RASP修改后的java.lang.ProcessBuilder类**

```java
package java.lang;

import org.javaweb.rasp.loader.hooks.RASPHookHandlerType;
import org.javaweb.rasp.loader.hooks.RASPHookProxy;
import org.javaweb.rasp.loader.hooks.RASPHookResult;

import java.io.IOException;
import java.util.List;

public final class ProcessBuilder {

	private List<String> command;

	public Process start() throws IOException {
      // 生成Object数组对象，存储方法参数值
      Object[] parameters = new Object[]{};

      // 生成try/catch
      try {
          // 调用RASP方法方法进入时检测逻辑
          RASPHookResult<?> enterResult = RASPHookProxy.onMethodEnter(parameters, ...);
          String HandlerType = enterResult.getRaspHookHandlerType().toString();

          if (RASPHookHandlerType.REPLACE_OR_BLOCK.toString().equals(HandlerType)) {
              // 如果RASP检测结果需要阻断或替换程序执行逻辑，return RASP返回结果中设置的返回值
              return (Process) enterResult.getReturnValue();
          } else if (RASPHookHandlerType.THROW.toString().equals(HandlerType)) {
              // 如果RASP检测结果需要往外抛出异常，throw RASP返回结果中设置的异常对象
              throw (Throwable) enterResult.getException();
          }

          // 执行程序原逻辑，执行本地系统命令并返回Process对象
          Process methodReturn = ProcessImpl.start(command, environment, dir, redirects, redirectErrorStream);

          // 调用RASP方法方法退出时检测逻辑，同onMethodEnter，此处省略对应代码

          return methodReturn;
      } catch (Throwable t) {
        	// 调用RASP方法方法异常退出时检测逻辑，同onMethodEnter，此处省略对应代码
      }
	}

}
```



## RASP Hook与Java Web攻击

常见的Java Web攻击方式最终几乎都会调用对应的Java类方法执行，而RASP恰好可以使用Hook机制控制任意的Java类方法执行逻辑，因此RASP可以使用Hook机制将易受攻击的Java类进行监控，从而实现防止恶意的Java Web攻击。

![img](https://oss.javasec.org/images/image-20201202201757182.png)

