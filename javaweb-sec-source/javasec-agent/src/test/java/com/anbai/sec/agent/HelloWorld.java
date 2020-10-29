package com.anbai.sec.agent;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Creator: yz
 * Date: 2020/10/29
 */
public class HelloWorld {

	private static void hello(String cmd) {
		// 获取当前系统时间
		String datetime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
		System.out.println("Time: " + datetime + "，执行命令：" + cmd);
	}

	public static void main(String[] args) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					try {
						// 调用hello方法
						hello("whoami");

						// sleep 1秒
						TimeUnit.SECONDS.sleep(1);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
	}

}