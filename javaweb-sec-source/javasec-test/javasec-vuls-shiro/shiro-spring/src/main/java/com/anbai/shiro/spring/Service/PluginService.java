package com.anbai.shiro.spring.Service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.anbai.shiro.spring.data.PluginRequest;

import java.io.*;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.UUID;

/**
 * @author su18
 */
@Service
public class PluginService {

	public String editPlugin(MultipartFile file) {
		String id   = UUID.randomUUID().toString();
		String path = create(id, file);
		this.getMethod(path, file.getOriginalFilename());
		return null;
	}

	private void getMethod(String path, String fileName) {
		this.loadJar(path);
	}

	private void loadJar(String jarPath) {
		File jarFile = new File(jarPath);
		// 从URLClassLoader类中获取类所在文件夹的方法，jar也可以认为是一个文件夹
		Method method = null;
		try {
			method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
		} catch (NoSuchMethodException | SecurityException e1) {
			e1.printStackTrace();
		}
		// 获取方法的访问权限以便写回
		try {
			method.setAccessible(true);
			// 获取系统类加载器
			URLClassLoader classLoader = (URLClassLoader) ClassLoader.getSystemClassLoader();

			URL url = jarFile.toURI().toURL();
			//URLClassLoader classLoader = new URLClassLoader(new URL[]{url});

			method.invoke(classLoader, url);
		} catch (Exception e) {
			System.out.println(e);
		}
	}


	public Object customMethod(PluginRequest request) {
		try {
			Class<?> clazz    = Class.forName(request.getEntry());
			Object   instance = clazz.newInstance();
			return clazz.getDeclaredMethod("customMethod", String.class).invoke(instance, request.getRequest());
		} catch (Exception ex) {
			System.out.println(ex);
		}
		return null;
	}

	public static String create(String id, MultipartFile item) {
		String filePath = "/tmp/plugin";
		if (item != null) {
			File testDir = new File(filePath);
			if (!testDir.exists()) {
				testDir.mkdirs();
			}
			File file = new File(filePath + "/" + id + "_" + item.getOriginalFilename());
			try (InputStream in = item.getInputStream(); OutputStream out = new FileOutputStream(file)) {
				file.createNewFile();
				final int MAX = 4096;
				byte[]    buf = new byte[MAX];
				for (int bytesRead = in.read(buf, 0, MAX); bytesRead != -1; bytesRead = in.read(buf, 0, MAX)) {
					out.write(buf, 0, bytesRead);
				}
			} catch (IOException e) {
				System.out.println(e);
			}
			return file.getPath();
		}
		return null;
	}
}

