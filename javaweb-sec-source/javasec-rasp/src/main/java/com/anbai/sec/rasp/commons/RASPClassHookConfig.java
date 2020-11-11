/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import com.anbai.sec.rasp.annotation.RASPMethodHook;
import org.javaweb.utils.ClassUtils;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 灵蜥类方法Hook配置类
 * <p>
 * Creator: yz
 * Date: 2019-06-24
 */
public class RASPClassHookConfig extends RASPHookConfig {

	/**
	 * 需要Hook的父类
	 */
	private String superClass;

	/**
	 * Hook时是否忽略父类自身
	 */
	private boolean ignoreSuperClassSelf;

	/**
	 * 是否忽略JDK内部API的类
	 */
	private boolean ignoreJDKInternalClass;

	/**
	 * 需要Hook的类名
	 */
	private String className;

	/**
	 * 类名是否使用正则表达式匹配
	 */
	private boolean classNameRegexp;

	/**
	 * 需要Hook的方法名
	 */
	private String methodName;

	/**
	 * 方法名是否使用正则表达式匹配
	 */
	private boolean methodNameRegexp;

	/**
	 * 需要Hook的方法名描述符
	 */
	private String methodDesc;

	/**
	 * 方法名是否使用正则表达式描述符
	 */
	private boolean methodDescRegexp;

	public RASPClassHookConfig(Class<?> invokeClass) {
		super(invokeClass);
	}

	public String getSuperClass() {
		return superClass;
	}

	public String getClassName() {
		return className;
	}

	public boolean isClassNameRegexp() {
		return classNameRegexp;
	}

	public String getMethodName() {
		return methodName;
	}

	public boolean isMethodNameRegexp() {
		return methodNameRegexp;
	}

	public String getMethodDesc() {
		return methodDesc;
	}

	public boolean isMethodDescRegexp() {
		return methodDescRegexp;
	}

	/**
	 * 获取所有Hook配置信息
	 *
	 * @return
	 */
	public void initHookConfigs() {
		RASPMethodHook methodHook = invokeClass.getAnnotation(RASPMethodHook.class);

		if (methodHook != null) {
			String   superClass       = methodHook.superClass();
			String   className        = methodHook.className();
			boolean  classNameRegexp  = methodHook.classNameRegexp();
			Class    onClass          = methodHook.onClass();
			String   methodName       = methodHook.methodName();
			boolean  methodNameRegexp = methodHook.methodNameRegexp();
			String   methodDesc       = methodHook.methodArgsDesc();
			String[] methodArgs       = methodHook.methodArgs();
			Class[]  methodDescClass  = methodHook.onMethodArgsDesc();
			boolean  methodDescRegexp = methodHook.methodDescRegexp();

			// 如果是通过指定XXX.class方式Hook,因为已经是全类名了所以需要禁止掉类名正则匹配
			if (onClass != void.class) {
				className = onClass.getName();
				classNameRegexp = false;
			}

			if (methodArgs.length > 0) {
				methodDesc = ClassUtils.getDescriptor(methodArgs);
			}

			if (methodDescClass.length > 0) {
				methodDesc = ClassUtils.getDescriptor(methodDescClass);
			}

			// 如果不是正则表达式需要转义类名中的特殊字符:比如"$"、".",如果是父类Hook,这里的类名可能为空
			if (!classNameRegexp && !"".equals(className)) {
				className = "^" + Pattern.quote(className) + "$";
			}

			if (!methodNameRegexp && !"".equals(methodName)) {
				methodName = "^" + Pattern.quote(methodName) + "$";
			}

			if (!methodDescRegexp && !"".equals(methodDesc)) {
				methodDesc = "^" + Pattern.quote(methodDesc) + "$";
			}

			// 设置需要Hook的父类或者接口
			this.superClass = superClass;

			// 设置Hook时是否忽略父类自身
			this.ignoreSuperClassSelf = methodHook.ignoreSuperClassSelf();

			// 设置是否忽略JDK内置的API类Hook
			this.ignoreJDKInternalClass = methodHook.ignoreJDKInternalClass();

			// 设置需要Hook的Class类名称
			this.className = className;
			this.classNameRegexp = classNameRegexp;

			// 设置需要Hook的Class类方法名称
			this.methodName = methodName;
			this.methodNameRegexp = methodNameRegexp;

			// 设置需要Hook的Class类方法描述符
			this.methodDesc = methodDesc;
			this.methodDescRegexp = methodDescRegexp;
		}
	}

	@Override
	public String getHookClassName() {
		return className;
	}

	@Override
	public String getHookSuperClassName() {
		return superClass;
	}

	@Override
	public String[] getHooKClassAnnotations() {
		return new String[0];
	}

	@Override
	public String[] getHooKMethodAnnotations() {
		return new String[0];
	}

	/**
	 * Hook类名匹配检测,如果设置了父类Hook那么不需要检测类名是否一致。
	 *
	 * @param classDesc
	 * @return
	 */
	public boolean classMatcher(RASPClassDesc classDesc) {
		// 检测是否忽略JDK内部的API类
		if (ignoreJDKInternalClass && classDesc.getClassLoader() == null) {
			return false;
		}

		// 比较两个类类名是否一致
		return nameMatcher(this.className, classDesc.getClassName());
	}

	/**
	 * Hook类名匹配检测,如果设置了父类Hook那么不需要检测类名是否一致。
	 *
	 * @param clazz
	 * @return
	 */
	@Override
	public boolean classMatcher(Class clazz) {
		// 忽略接口类,因为接口不需要被增强,不用忽略抽象类,可以在方法匹配时检测是否是抽象方法
		if (clazz.isInterface()) {
			return false;
		}

		if (!Object.class.getName().equals(superClass)) {
			Set<String> superClassList = ClassUtils.getSuperClassListByAsm(clazz.getName(), clazz.getClassLoader());

			if (superClassList.contains(superClass)) {
				return true;
			}
		}

		return clazz.getName().equals(className);
	}

	/**
	 * Hook类的方法名和描述符匹配
	 *
	 * @param methodConfigs
	 * @return
	 */
	private boolean methodMatcher(Object[] methodConfigs) {
		for (Object methodConfig : methodConfigs) {
			Object[] objects = (Object[]) methodConfig;
			String   regexp  = (String) objects[0];
			String   content = (String) objects[1];

			if (!nameMatcher(regexp, content)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * 忽略返回值，确定一个方法是否需要Hook只要方法名和方法入参一致就行了,这里只保留参数描述符"()"内的参数描述符
	 *
	 * @param methodArgsDesc
	 * @return
	 */
	private String replaceMethodArgs(String methodArgsDesc) {
		return methodArgsDesc.replaceAll("^\\(", "").replaceAll("\\).*$", "");
	}

	/**
	 * 检测Hook点与当前传入的类名、方法名、方法描述符是否匹配(不包含返回值)
	 *
	 * @param methodDesc
	 * @return
	 */
	@Override
	public Set<RASPHookConfig> methodMatcher(RASPMethodDesc methodDesc) {
		Set<RASPHookConfig> matchedHooks    = new LinkedHashSet<RASPHookConfig>();
		String              methodName      = methodDesc.getMethodName();
		String              methodSignature = methodDesc.getMethodSignature();
		String              methodArg       = replaceMethodArgs(methodSignature);

		Object[] methodConfigs = new Object[]{
				new Object[]{this.methodName, methodName},// 方法名匹配检测
				new Object[]{this.methodDesc, methodArg}// 方法描述符匹配检测
		};

		if (methodMatcher(methodConfigs)) {
			matchedHooks.add(this);
		}

		return matchedHooks;
	}

	/**
	 * 类名/方法名/方法描述符正则匹配
	 *
	 * @param regexp  名称
	 * @param content 匹配的内容
	 * @return
	 */
	private boolean nameMatcher(String regexp, String content) {
		if ("".equals(regexp) && !"".equals(content)) {
			return false;
		}

		return Pattern.compile(regexp).matcher(content).find();
	}

	@Override
	public String toString() {
		return "RASPClassHookConfig{" +
				"superClass='" + superClass + '\'' +
				", className='" + className + '\'' +
				", classNameRegexp=" + classNameRegexp +
				", methodName='" + methodName + '\'' +
				", methodNameRegexp=" + methodNameRegexp +
				", methodDesc='" + methodDesc + '\'' +
				", methodDescRegexp=" + methodDescRegexp +
				", invokeClass=" + invokeClass +
				'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof RASPClassHookConfig)) return false;

		RASPClassHookConfig that = (RASPClassHookConfig) o;

		if (classNameRegexp != that.classNameRegexp) return false;
		if (methodNameRegexp != that.methodNameRegexp) return false;
		if (methodDescRegexp != that.methodDescRegexp) return false;
		if (superClass != null ? !superClass.equals(that.superClass) : that.superClass != null) return false;
		if (className != null ? !className.equals(that.className) : that.className != null) return false;
		if (methodName != null ? !methodName.equals(that.methodName) : that.methodName != null) return false;

		return methodDesc != null ? methodDesc.equals(that.methodDesc) : that.methodDesc == null;
	}

	@Override
	public int hashCode() {
		int result = superClass != null ? superClass.hashCode() : 0;
		result = 31 * result + (className != null ? className.hashCode() : 0);
		result = 31 * result + (classNameRegexp ? 1 : 0);
		result = 31 * result + (methodName != null ? methodName.hashCode() : 0);
		result = 31 * result + (methodNameRegexp ? 1 : 0);
		result = 31 * result + (methodDesc != null ? methodDesc.hashCode() : 0);
		result = 31 * result + (methodDescRegexp ? 1 : 0);

		return result;
	}

}
