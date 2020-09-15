package com.anbai.sec.server.loader;

import java.net.URL;
import java.net.URLClassLoader;

public class BinCatWebAppClassLoader extends URLClassLoader {

	public BinCatWebAppClassLoader(URL[] urls, ClassLoader parent) {
		super(urls, parent);
	}

}
