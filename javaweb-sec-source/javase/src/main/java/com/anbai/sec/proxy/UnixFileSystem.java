package com.anbai.sec.proxy;

import java.io.File;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class UnixFileSystem implements FileSystem {

	/* -- Disk usage -- */
	public int spaceTotal = 996;

	@Override
	public String[] list(File file) {
		System.out.println("正在执行[" + this.getClass().getName() + "]类的list方法，参数:[" + file + "]");

		return file.list();
	}

}
