/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import com.anbai.sec.rasp.annotation.RASPClassHook;
import com.anbai.sec.rasp.annotation.RASPMethodHook;
import org.javaweb.utils.ClassUtils;
import org.javaweb.utils.StringUtils;

import java.lang.annotation.Annotation;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import static com.anbai.sec.rasp.commons.RASPConstants.AGENT_NAME;
import static com.anbai.sec.rasp.commons.RASPConstants.AGENT_PACKAGE_PREFIX;

/**
 * 灵蜥Hook加载类
 * Creator: yz
 * Date: 2019-07-20
 */
public class RASPHookLoader {

	/**
	 * 获取一个类中的所有内部类
	 *
	 * @param clazz
	 * @param classList
	 */
	private static void getAllInnerClass(Class<?> clazz, Set<Class<?>> classList) {
		Class[] classes = clazz.getDeclaredClasses();

		for (Class c : classes) {
			if (c.getDeclaredClasses().length > 0) {
				getAllInnerClass(c, classList);
			}

			classList.add(c);
		}
	}

	/**
	 * 加载灵蜥Hooks目录jar文件
	 *
	 * @param agentFile Agent File
	 * @return Agent Hook配置
	 */
	public static Set<RASPClassHookConfig> loadHooks(JarFile agentFile) {
		Set<RASPClassHookConfig> hookConfigs = new LinkedHashSet<RASPClassHookConfig>();

		try {
			Enumeration<JarEntry> entries = agentFile.entries();

			while (entries.hasMoreElements()) {
				JarEntry jarEntry = entries.nextElement();
				String   fileName = jarEntry.getName();

				if (!fileName.startsWith("META-INF/") && fileName.endsWith(".class")) {
					String className = fileName.replaceAll("\\.class$", "").replace("/", ".");

					// 排除package-info、module-info.class类
					if (className.endsWith("package-info") || className.endsWith("module-info")) {
						continue;
					}

					// RASP Hook包名
					String hookPackage = AGENT_PACKAGE_PREFIX + "hooks";

					if (className.startsWith(hookPackage)) {
						Class<?>   clazz     = Class.forName(className, false, ClassLoader.getSystemClassLoader());
						Annotation classHook = clazz.getAnnotation(RASPClassHook.class);

						if (classHook != null) {
							Set<Class<?>> classList = new LinkedHashSet<Class<?>>();
							getAllInnerClass(clazz, classList);

							for (Class<?> c : classList) {
								// 只添加RASPMethodAdvice子类
								if (RASPMethodAdvice.class.isAssignableFrom(c)) {
									RASPMethodHook methodHook = c.getAnnotation(RASPMethodHook.class);

									if (methodHook != null) {
										hookConfigs.add(new RASPClassHookConfig(c));
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			new RuntimeException(AGENT_NAME + "初始化Hook JAR异常:" + e, e).printStackTrace();
		}

		return hookConfigs;
	}


	/**
	 * Hook父类匹配检测,排除自身是Object类的情况
	 *
	 * @param clazz  类对象
	 * @param config ReTransform 配置
	 * @return 是否是父类
	 */
	private static boolean superClassMatcher(Class clazz, RASPReTransformClass config) {
		String hookSuperClassName = config.getSuperClassName();

		if (Object.class.getName().equals(clazz.getName()) || StringUtils.isEmpty(hookSuperClassName)) {
			return false;
		}

		Set<Class> classes = ClassUtils.getSuperClassList(clazz);

		for (Class superClass : classes) {
			if (superClass.getName().equals(hookSuperClassName)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Hook类名检测
	 *
	 * @param className
	 * @param config
	 * @return
	 */
	private static boolean classNameMatcher(String className, RASPReTransformClass config) {
		String hookClassName = config.getClassName();

		if (StringUtils.isNotEmpty(hookClassName)) {
			return Pattern.compile(hookClassName).matcher(className).find();
		}

		return false;
	}

	/**
	 * 获取所有需要Hook的类名称，包含了配置文件指定的类、通过配置文件反向去JVM中LoadedClasses中获取的类
	 *
	 * @param hookConfigs
	 * @return
	 */
	public static Set<RASPReTransformClass> getReTransformConfigs(Set<RASPClassHookConfig> hookConfigs) {
		Set<RASPReTransformClass> reTransformConfigs = new HashSet<RASPReTransformClass>();

		// 添加配置文件中需要ReTransform的类
		for (RASPClassHookConfig config : hookConfigs) {
			String               className         = config.getHookClassName();
			String               superClassName    = config.getHookSuperClassName();
			String[]             classAnnotations  = config.getHooKClassAnnotations();
			String[]             methodAnnotations = config.getHooKMethodAnnotations();
			RASPReTransformClass reTransformClass  = new RASPReTransformClass();

			if (StringUtils.isNotEmpty(className)) {
				reTransformClass.setClassName(className);
			} else if (StringUtils.isNotEmpty(superClassName)) {
				reTransformClass.setSuperClassName(superClassName);
			} else {
				reTransformClass.setClassAnnotations(classAnnotations);
				reTransformClass.setMethodAnnotations(methodAnnotations);
			}

			reTransformConfigs.add(reTransformClass);
		}

		return reTransformConfigs;
	}

	/**
	 * 设置需要reTransform的类
	 *
	 * @param inst               Agent inst对象
	 * @param reTransformConfigs reTransform 配置
	 */
	public static void setReTransformClasses(
			Instrumentation inst, Set<RASPReTransformClass> reTransformConfigs, RASPAgentCache agentCache) {

		Class<?>[] allLoadedClasses = inst.getAllLoadedClasses();

		// 添加已经被JVM加载的类中需要ReTransform的类
		for (Class<?> clazz : allLoadedClasses) {
			String className = clazz.getName();

			for (RASPReTransformClass config : reTransformConfigs) {
				// 如果父类名、类名、类和方法注解检测的任意一个条件满足且该类允许被修改则ReTransform
				if ((superClassMatcher(clazz, config) || classNameMatcher(className, config))
						&& inst.isModifiableClass(clazz)) {

					try {
						agentCache.getReTransformClass().add(clazz.getName());

						System.out.println(AGENT_NAME + " ReTransform " + clazz.getName() + " class");

						inst.retransformClasses(clazz);
						break;
					} catch (UnmodifiableClassException e) {
						new RuntimeException(AGENT_NAME + "设置ReTransform异常:" + e, e).printStackTrace();
					}
				}
			}
		}
	}

}
