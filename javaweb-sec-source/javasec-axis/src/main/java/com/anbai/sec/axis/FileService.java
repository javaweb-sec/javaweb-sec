package com.anbai.sec.axis;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

/**
 * @author yz
 */
public class FileService {

	public String readFile(String path) {
		if (path != null && !"".equals(path)) {
			File file = new File(path);

			if (file.exists()) {
				try {
					return FileUtils.readFileToString(file, "UTF-8");
				} catch (IOException e) {
					return "读取文件:" + file + "异常:" + e;
				}
			} else {
				return "文件:" + file + "不存在!";
			}
		} else {
			return "path不能为空!";
		}
	}

	public String writeFile(String path, String content) {
		if (path != null && !"".equals(path)) {
			File file = new File(path);

			try {
				FileUtils.writeStringToFile(file, content, "UTF-8");

				return file.getAbsolutePath();
			} catch (IOException e) {
				return "写文件:" + file + "异常:" + e;
			}
		}

		return "path不能为空!";
	}

	public String test() {
		return "文件WebService测试~";
	}

}
