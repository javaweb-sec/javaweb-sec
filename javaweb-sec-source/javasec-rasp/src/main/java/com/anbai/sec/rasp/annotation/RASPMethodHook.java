/**
 * ----------------------------------------------------------------------
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 * ----------------------------------------------------------------------
 */
package com.anbai.sec.rasp.annotation;

import java.lang.annotation.*;

/**
 * 灵蜥类方法Hook注解
 * Creator:
 * Date:
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RASPMethodHook {

	/**
	 * 需要Hook的类名
	 */
	String className() default "";

	/**
	 * 需要Hook的类
	 */
	Class onClass() default void.class;

	/**
	 * 需要Hook的父类类名，父类Hook时类名不允许使用正则表达式
	 *
	 * @return
	 */
	String superClass() default "java.lang.Object";

	/**
	 * 是否忽略父类自身，如果使用了父类Hook，配置该选项可设置是否将父类也同时Hook了
	 *
	 * @return
	 */
	boolean ignoreSuperClassSelf() default false;

	/**
	 * 是否忽略JDK内置的API类Hook
	 *
	 * @return
	 */
	boolean ignoreJDKInternalClass() default false;

	/**
	 * 类名是否使用正则表达式匹配，父类Hook时类名不允许使用正则表达式
	 */
	boolean classNameRegexp() default false;

	/**
	 * 需要Hook的方法名
	 */
	String methodName();

	/**
	 * 方法名是否使用正则表达式匹配
	 */
	boolean methodNameRegexp() default false;

	/**
	 * 需要Hook的方法参数名数组
	 */
	String[] methodArgs() default {};

	/**
	 * 需要Hook的方法名描述符,如果配置此项需要使用方法描述符方式写,
	 * 如:Ljava/lang/String;来表示接收个字符串类型参数
	 *
	 * @return
	 */
	String methodArgsDesc() default "";

	/**
	 * 需要Hook的方法名参数类型,需要保持和原方法的顺序一致
	 */
	Class[] onMethodArgsDesc() default {};

	/**
	 * 方法名是否使用正则表达式描述符
	 */
	boolean methodDescRegexp() default false;

}
