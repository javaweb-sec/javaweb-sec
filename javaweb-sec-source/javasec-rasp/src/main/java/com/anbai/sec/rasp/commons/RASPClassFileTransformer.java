package com.anbai.sec.rasp.commons;

import javassist.*;
import org.javaweb.utils.FileUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.regex.Pattern;

import static com.anbai.sec.rasp.commons.RASPConstants.PROTECTED_PACKAGE_PATTERN;
import static javassist.Modifier.isAbstract;
import static javassist.Modifier.isNative;

public class RASPClassFileTransformer implements ClassFileTransformer {

	private final Set<RASPClassHookConfig> hookConfigs;

	public RASPClassFileTransformer(Set<RASPClassHookConfig> hookConfigs) {
		this.hookConfigs = hookConfigs;
	}

	/**
	 * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
	 *
	 * @param classLoader         定义要转换的类加载器；如果是引导加载器，则为 null
	 * @param className           类名,如:java/lang/Runtime
	 * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
	 * @param protectionDomain    要定义或重定义的类的保护域
	 * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
	 * @return 字节码byte数组。
	 */
	@Override
	public byte[] transform(ClassLoader classLoader, String className, Class<?> classBeingRedefined,
	                        ProtectionDomain protectionDomain, byte[] classfileBuffer) {

		// 将目录路径替换成Java类名
		className = className.replace("/", ".");

		// 排除和java系统底层核心的类、Agent自身和依赖库、其他可能无法处理的类
		if (PROTECTED_PACKAGE_PATTERN.matcher(className).find()) {
			return classfileBuffer;
		}

		try {
			// 创建ClassPool
			ClassPool classPool = ClassPool.getDefault();

			// 添加ClassPath
			if (classLoader != null) {
				classPool.insertClassPath(new LoaderClassPath(classLoader));
			}

			for (RASPClassHookConfig hookConfig : hookConfigs) {
				String hookClassName = hookConfig.getHookClassName();

				// 如果Hook的类名未设置就使用父类Hook的方式
				boolean superClassHook = "".equals(hookClassName);

				// 检测是否是指定类名称的Hook方式
				if (!(superClassHook || Pattern.compile(className).matcher(hookClassName).find())) {
					continue;
				}

				// 使用javassist将类二进制解析成CtClass对象
				CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

				// 不Hook接口类
				if (ctClass.isInterface()) {
					continue;
				}

				// 获取当前类的所有方法
				CtMethod[] ctMethods = ctClass.getDeclaredMethods();

				// 获取当前类的所有构造方法
				CtConstructor[] ctConstructors = ctClass.getDeclaredConstructors();

				// 遍历所有的类方法
				for (CtMethod ctMethod : ctMethods) {
					int access = ctMethod.getModifiers();

					// 不编辑native方法和抽象方法
					if (isNative(access) || isAbstract(access)) {
						break;
					}

					editMethod(classPool, className, ctMethod, superClassHook, hookConfig);
				}

				for (CtConstructor ctConstructor : ctConstructors) {
					editMethod(classPool, className, ctConstructor, superClassHook, hookConfig);
				}

				// 修改后的类字节码
				classfileBuffer = ctClass.toBytecode();

				String regexp = "(ProcessBuilder|WsFilter|StrutsPrepareAndExecuteFilter)$";

				if (Pattern.compile(regexp).matcher(className).find()) {
					className = className.substring(className.lastIndexOf(".") + 1);
					File file = new File("/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-rasp/src/main/java/com/anbai/sec/rasp/", className + ".class");
					FileUtils.writeByteArrayToFile(file, classfileBuffer);
				}

				ctClass.detach();
			}
		} catch (Throwable t) {
			t.printStackTrace();
		}

		return classfileBuffer;
	}

	private void editMethod(ClassPool classPool, String className, CtBehavior ctBehavior,
	                        boolean superClassHook, RASPClassHookConfig hookConfig) throws Exception {

		// 方法名称
		String methodName = ctBehavior.getName();

		// 方法描述符
		String signature = ctBehavior.getSignature();

		// 方法进入时插入的代码
		StringBuilder onMethodEnter = new StringBuilder();

		// 方法退出时插入的代码
		StringBuilder onMethodExit = new StringBuilder();

		StringBuilder loadClass    = new StringBuilder();
		StringBuilder invokeResult = new StringBuilder();

		// 创建类方法描述对象
		RASPMethodDesc methodDesc = new RASPMethodDesc(
				ctBehavior.getModifiers(), signature, ctBehavior.getExceptionTypes(), methodName
		);

		// 匹配Hook到的配置
		Set<RASPHookConfig> hookMatchedList = hookConfig.methodMatcher(methodDesc);

		// 检测当前方法是否匹配到了Hook点规则
		if (!hookMatchedList.isEmpty()) {
			loadClass.append("try {");

			for (RASPHookConfig raspHookConfig : hookMatchedList) {
				// 获取父类的类名称
				String superClassName = raspHookConfig.getHookSuperClassName();

				// 获取Hook点回调方法的类名称
				String callbackClass = raspHookConfig.getInvokeClass().getName();

				if (superClassHook) {
					loadClass.append("Class thisClass = Class.forName(\"").append(className).append("\");")
							.append("Class superClass = Class.forName(\"").append(superClassName).append("\");")
							.append("if (superClass.isAssignableFrom(thisClass)) {");
				}

				String commonsPkg = "com.anbai.sec.rasp.commons.";

				String beforeStr = commonsPkg + "RASPHookResult result = " + commonsPkg + "RASPHookProxy.onMethodEnter($args, \"" + callbackClass + "\", \"" + className + "\", \"" + methodName + "\", \"" + signature + "\", $0);";
				String afterStr  = commonsPkg + "RASPHookResult result = " + commonsPkg + "RASPHookProxy.onMethodExit($_, $args, \"" + callbackClass + "\", \"" + className + "\", \"" + methodName + "\", \"" + signature + "\", $0);";

				invokeResult.append("String handlerType = result.getRaspHookHandlerType().toString();");
				invokeResult.append("if (\"REPLACE_OR_BLOCK\".equals(handlerType)) {");

				// 处理普通方法和构造方法的返回值
				if (ctBehavior instanceof CtMethod) {
					// 获取方法的返回类型
					CtClass returnType = ((CtMethod) ctBehavior).getReturnType();

					// 计算当前的方法是否需要返回对象，如果有返回值就强转成对应的数据类型，否则直接return;
					if ("void".equals(returnType.getName())) {
						invokeResult.append("return;");
					} else {
						// 强制类型转换
						invokeResult.append("return (").append(returnType.getSimpleName()).append(")result.getReturnValue();");
					}
				} else {
					// 构造方法只需要return，不需要再创建该类的实例了，不然可能就死循环了
					invokeResult.append("return;");
				}

				invokeResult.append("} else if (\"THROW\".equals(handlerType)) {")
						.append("   throw (Exception) result.getException();")
						.append("}");


				if (superClassHook) {
					invokeResult.append("}");
				}

				onMethodEnter.append(loadClass).append(beforeStr);
				onMethodExit.append(loadClass).append(afterStr);

				break;
			}

			invokeResult.append("} catch (Exception e) {")
					.append("  if (\"RASPHookException\".equals(e.getClass().getSimpleName())) {")
					.append("     throw e;")
					.append("  }")
					.append("}");

			onMethodEnter.append(invokeResult);
			onMethodExit.append(invokeResult);
		}

		// 检测是否需要编辑类代码，如果onMethodEnter不为空那么就需要修改方法代码，需要插入：方法进入、退出、异常这三类事件的处理逻辑
		if (onMethodEnter.length() > 0) {
			// 先插入After代码，不然插入的Before代码也会被After的逻辑包裹
			ctBehavior.insertAfter(onMethodExit.toString());

			// 处理普通方法和构造方法插入before的代码逻辑
			if (ctBehavior instanceof CtMethod) {
				// 插入Before代码，也就是修改方法进入时的业务逻辑
				ctBehavior.insertBefore(onMethodEnter.toString());
			} else {
				// 构造方法如果父类有参数，那么必须先super(xxx);调用父类的构造方法，否则会报错，所以
				// 需要使用insertBeforeBody插入代码而不是insertBefore
				((CtConstructor) ctBehavior).insertBeforeBody(onMethodEnter.toString());
			}

			// 方法异常捕获，插入到最后面，捕获整个方法的异常信息
			ctBehavior.addCatch("{throw $e;}", classPool.get("java.lang.Throwable"));
		}
	}

}
