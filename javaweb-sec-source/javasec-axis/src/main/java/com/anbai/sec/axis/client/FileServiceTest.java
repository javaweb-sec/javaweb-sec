package com.anbai.sec.axis.client;

import java.net.URL;

/**
 * 文件Web Service服务测试
 *
 * @author yz
 */
public class FileServiceTest {

	public static void main(String[] args) {
		try {
			FileServiceService         fileService   = new FileServiceServiceLocator();
			URL                        webServiceUrl = new URL("http://localhost:8080/services/FileService");
			FileServiceSoapBindingStub soapService   = new FileServiceSoapBindingStub(webServiceUrl, fileService);

			String content = soapService.readFile("/etc/passwd");

			System.out.println(content);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
