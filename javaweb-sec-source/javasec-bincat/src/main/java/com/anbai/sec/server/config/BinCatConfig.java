package com.anbai.sec.server.config;

import com.anbai.sec.server.loader.BinCatWebAppClassLoader;
import com.anbai.sec.server.servlet.BinCatServletConfig;
import com.anbai.sec.server.servlet.BinCatServletContext;
import com.anbai.sec.server.servlet.BinCatServletRegistrationDynamic;
import com.anbai.sec.server.test.servlet.CMDServlet;
import com.anbai.sec.server.test.servlet.QuercusPHPServlet;
import com.anbai.sec.server.test.servlet.TestServlet;
import com.anbai.sec.utils.ClassUtils;
import org.javaweb.utils.FileUtils;
import org.javaweb.utils.IOUtils;

import javax.servlet.Servlet;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletRegistration;
import javax.servlet.annotation.HandlesTypes;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class BinCatConfig {

	public static BinCatServletContext createServletContext() throws Exception {
		return createServletContext(null);
	}

	/**
	 * 手动注册Servlet并创建BinCatServletContext对象
	 *
	 * @param appClassLoader
	 * @return ServletContext
	 */
	public static BinCatServletContext createServletContext(BinCatWebAppClassLoader appClassLoader) throws Exception {
		BinCatServletContext servletContext = new BinCatServletContext(appClassLoader);

		// 手动注册Servlet类
		Class<Servlet>[] servletClass = new Class[]{
//				IndexServlet.class,
				TestServlet.class,
				CMDServlet.class,
				QuercusPHPServlet.class
		};

		for (Class<Servlet> clazz : servletClass) {
			Servlet    servlet    = clazz.newInstance();
			WebServlet webServlet = clazz.getAnnotation(WebServlet.class);

			if (webServlet != null) {
				// 获取WebInitParam配置
				WebInitParam[] webInitParam = webServlet.initParams();

				// 动态创建Servlet对象
				ServletRegistration.Dynamic dynamic = servletContext.addServlet(webServlet.name(), servlet);

				// 动态设置Servlet映射地址
				dynamic.addMapping(webServlet.urlPatterns());

				// 设置Servlet启动参数
				for (WebInitParam initParam : webInitParam) {
					dynamic.setInitParameter(initParam.name(), initParam.value());
				}
			}
		}

		// 创建ServletContext
		return servletContext;
	}

	public static BinCatWebAppClassLoader createAppClassLoader(String webAppFile) throws IOException {
		File     webRoot      = new File(webAppFile);
		File     webInfoDir   = new File(webRoot, "WEB-INF");
		File     libDir       = new File(webInfoDir, "lib");
		File     classesDir   = new File(webInfoDir, "classes");
		Set<URL> classPathURL = new HashSet<>();

		File[] libs = libDir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".jar");
			}
		});

		// 加载lib目录下所有的jar文件
		for (File lib : libs) {
			classPathURL.add(lib.toURL());
		}

		// 加载classes目录的所有资源文件
		classPathURL.add(classesDir.toURL());

		// 创建Web应用的类加载器
		return new BinCatWebAppClassLoader(
				classPathURL.toArray(new URL[classPathURL.size()]), BinCatConfig.class.getClassLoader()
		);
	}

	public static void startWebApp(BinCatServletContext servletContext) throws Exception {
		BinCatWebAppClassLoader classLoader    = (BinCatWebAppClassLoader) servletContext.getClassLoader();
		String                  servletService = "META-INF/services/javax.servlet.ServletContainerInitializer";

		// 获取当前ClassLoader中的所有ServletContainerInitializer配置
		Enumeration<URL> resources = classLoader.getResources(servletService);

		// 获取SPI中定义的ServletContainerInitializer
		Map<ServletContainerInitializer, Set<Class<?>>> sciClassMap     = new LinkedHashMap<>();
		Map<ServletContainerInitializer, Class<?>[]>    handlesTypesMap = new LinkedHashMap<>();

		// 遍历从ClassLoader中获取到的所有ServletContainerInitializer配置
		while (resources.hasMoreElements()) {
			// 打开ServletContainerInitializer对应的文件流对象
			InputStream in = resources.nextElement().openStream();

			// 按行读取ServletContainerInitializer配置内容
			List<String> content = IOUtils.readLines(in);

			for (String className : content) {
				// 排除注释行
				if (!className.startsWith("#")) {
					// 反射创建ServletContainerInitializer配置的实例
					Class<?>                    initClass    = Class.forName(className, true, classLoader);
					HandlesTypes                handlesTypes = initClass.getAnnotation(HandlesTypes.class);
					ServletContainerInitializer sci          = (ServletContainerInitializer) initClass.newInstance();

					sciClassMap.put(sci, new HashSet<Class<?>>());

					if (handlesTypes != null) {
						Class[] handlesClass = handlesTypes.value();

						handlesTypesMap.put(sci, handlesClass);
					}
				}
			}
		}

		findInitializerClass(classLoader, sciClassMap, handlesTypesMap);

		for (ServletContainerInitializer initializer : sciClassMap.keySet()) {
			Set<Class<?>> initClassSet = sciClassMap.get(initializer);

			initializer.onStartup(initClassSet, servletContext);
		}

		Set<BinCatServletRegistrationDynamic> dynamics = servletContext.getRegistrationDynamics();

		for (BinCatServletRegistrationDynamic dynamic : dynamics) {
			Servlet             servlet          = dynamic.getServlet();
			String              servletName      = dynamic.getServletName();
			Map<String, String> initParameterMap = dynamic.getInitParameters();

			servlet.init(new BinCatServletConfig(servletContext, servletName, initParameterMap));
		}
	}

	/**
	 * 获取BinCatWebAppClassLoader类加载器加载的所有class类名
	 *
	 * @param classLoader
	 * @param sciClassMap
	 * @param handlesTypesMap
	 * @return
	 * @throws Exception
	 */
	private static void findInitializerClass(
			BinCatWebAppClassLoader classLoader,
			Map<ServletContainerInitializer, Set<Class<?>>> sciClassMap,
			Map<ServletContainerInitializer, Class<?>[]> handlesTypesMap) throws Exception {

		Set<String> classList = new HashSet<>();
		URL[]       urls      = classLoader.getURLs();

		for (URL url : urls) {
			File file = new File(url.toURI());

			if (file.isFile() && file.getName().endsWith(".jar")) {
				JarFile               jarFile  = new JarFile(file);
				Enumeration<JarEntry> jarEntry = jarFile.entries();

				while (jarEntry.hasMoreElements()) {
					JarEntry entry    = jarEntry.nextElement();
					String   fileName = entry.getName();

					if (fileName.endsWith(".class")) {
						String className = fileName.replace(".class", "").replace("/", ".");
						classList.add(className);
					}
				}
			} else if (file.isDirectory()) {
				Collection<File> files = FileUtils.listFiles(file, new String[]{"class"}, true);

				for (File classFile : files) {
					String className = classFile.toString().substring(file.toString().length())
							.replace(".class", "").replaceAll("^/", "").replace("/", ".");

					classList.add(className);
				}
			}
		}

		for (String className : classList) {
			Set<String> superClassList = ClassUtils.getSuperClassListByAsm(className, classLoader);

			for (ServletContainerInitializer sci : handlesTypesMap.keySet()) {
				Class[] handlesTypesClass = handlesTypesMap.get(sci);

				for (Class typesClass : handlesTypesClass) {
					String typeClassName = typesClass.getName();

					if (superClassList.contains(typeClassName) && !className.equals(typeClassName)) {
						Set<Class<?>> sciClass = sciClassMap.get(sci);
						Class         clazz    = classLoader.loadClass(className);

						sciClass.add(clazz);
					}
				}
			}
		}
	}

}
