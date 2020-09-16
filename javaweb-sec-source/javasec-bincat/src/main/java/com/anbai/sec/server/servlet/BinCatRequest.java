package com.anbai.sec.server.servlet;

import org.javaweb.utils.StringUtils;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.net.Socket;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * BinCat 请求解析实现对象，解析Http请求协议和参数
 */
public class BinCatRequest implements HttpServletRequest {

	// 客户端Socket连接对象
	private final Socket clientSocket;

	// Socket输入流对象
	private final InputStream socketInputStream;

	// Http请求头对象
	private Map<String, String> headerMap;

	// Http请求参数对象
	private Map<String, String[]> parameterMap;

	// Http请求attribute对象
	private final Map<String, Object> attributeMap = new ConcurrentHashMap<String, Object>();

	// Http请求Cookie对象
	private Cookie[] cookie;

	// Http请求Cookie对象
	private final Map<String, String> cookieMap = new ConcurrentHashMap<String, String>();

	// Http请求Session对象
	private final Map<String, BinCatSession> sessionMap = new ConcurrentHashMap<String, BinCatSession>();

	// Http请求方法类型
	private String requestMethod;

	// Http请求URL
	private String requestURL;

	// Http请求QueryString
	private String queryString;

	// Http请求协议版本信息
	private String httpVersion;

	// 是否已经解析过Http请求参数，防止多次解析请求参数
	private volatile boolean parsedParameter = false;

	// Http请求内容长度
	private int contentLength;

	// Http请求内容类型
	private String contentType;

	// 存储Session的ID名称
	private static final String SESSION_ID_NAME = "JSESSIONID";

	// Http请求主机名
	private String host;

	// Http请求主机端口
	private int port;

	private ServletContext servletContext;

	private static final Logger LOG = Logger.getLogger("info");

	private String characterEncoding;

	public BinCatRequest(Socket clientSocket) throws IOException {
		this(clientSocket, null);
	}

	public BinCatRequest(Socket clientSocket, ServletContext servletContext) throws IOException {
		this.clientSocket = clientSocket;
		this.socketInputStream = clientSocket.getInputStream();
		this.servletContext = servletContext;

		// 解析Http协议
		parse();
	}

	/**
	 * 解析Http请求协议，不解析Body部分
	 *
	 * @throws IOException
	 */
	private void parse() throws IOException {
		// 创建数据输出流对象
		DataInputStream dis = new DataInputStream(this.socketInputStream);

		// 从Socket中读取一行数据，读取请求的URL
		String str = dis.readLine();

		if (str == null) {
			throw new IOException("解析Http协议异常!");
		}

		// 切割请求Http协议信息
		String[] strs = str.split("\\s+");

		// 解析Http请求方法类型
		this.requestMethod = strs[0];

		// 解析Http请求URL地址
		String url = strs[1];

		// 初始化Http请求URL地址
		this.requestURL = url;

		// 解析Http请求版本信息
		this.httpVersion = strs[2];

		// 创建Header对象
		this.headerMap = new ConcurrentHashMap<String, String>();

		// 初始化请求参数数组
		this.parameterMap = new ConcurrentHashMap<String, String[]>();

		// 解析GET请求参数
		if (url.contains("?")) {
			String[] parameterStrs = url.split("\\?");
			this.requestURL = parameterStrs[0];

			// 初始化Http请求的QueryString
			this.queryString = parameterStrs[1];

			// 按"&"切割GET请求的参数
			String[] parameters = queryString.split("&");

			// 解析GET请求参数
			for (String parameter : parameters) {
				String[] tmp = parameter.split("=", -1);

				if (tmp.length == 2) {
					parameterMap.put(tmp[0], new String[]{URLDecoder.decode(tmp[1])});
				}
			}
		}

		// 解析请求头信息
		while (true) {
			// 按行读取Header头信息
			String line = dis.readLine();

			// 当读取到空行时停止解析Header
			if ("".equals(line)) {
				break;
			}

			// 切割Header的Key/Value
			String[] headers = line.split(":\\s*", -1);

			headerMap.put(headers[0], headers[1]);
		}

		// 解析Cookie
		if (headerMap.containsKey("cookie")) {
			// 切分Cookie字符串
			String[] cookies = headerMap.get("cookie").split(";\\s+", -1);

			// 初始化Cookie数组长度
			this.cookie = new Cookie[cookies.length];

			for (int i = 0; i < cookies.length; i++) {
				String   cookieStr = cookies[i];
				String[] tmp       = cookieStr.split("=", -1);

				if (tmp.length == 2) {
					// 创建Cookie对象
					this.cookie[i] = new Cookie(tmp[0], URLDecoder.decode(tmp[1]));
				}
			}
		}

		// 解析Http请求Host信息
		if (headerMap.containsKey("host")) {
			String[] hostStr = headerMap.get("host").split(":", -1);
			this.host = hostStr[0];
			this.port = !"".equals(hostStr[1]) ? Integer.parseInt(hostStr[1]) : 80;
		}

		this.contentType = headerMap.get("Content-Type");
	}

	/**
	 * 解析Http请求参数
	 *
	 * @throws IOException Http协议解析异常
	 */
	private synchronized void parseParameter() {
		try {
			// 检测是否重复解析，不用解析GET请求Body
			if (!parsedParameter && !"GET".equalsIgnoreCase(requestMethod)) {
				// 获取请求的主体长度
				this.contentLength = Integer.parseInt(headerMap.get("Content-Length"));

				if (contentLength > 0) {
					// 创建一个和请求体一样大小的缓冲区
					byte[] bytes = new byte[contentLength];

					// 读取POST主体内容
					this.socketInputStream.read(bytes);

					// 解析POST请求内容
					String body = new String(bytes, "UTF-8");

					// 按"&"切割POST请求的参数
					String[] parameters = body.split("&");

					// 解析POST请求参数
					for (String parameter : parameters) {
						String[] tmp = parameter.split("=", -1);

						if (tmp.length == 2) {
							parameterMap.put(tmp[0], new String[]{URLDecoder.decode(tmp[1], "UTF-8")});
						}
					}
				}
			}
		} catch (IOException e) {
			LOG.info("解析请求参数异常:" + e);
		}

		// 修改解析参数状态为已解析
		this.parsedParameter = true;
	}

	public String getAuthType() {
		return null;
	}

	public Cookie[] getCookies() {
		return this.cookie;
	}

	public long getDateHeader(String name) {
		return -1L;
	}

	public String getHeader(String name) {
		return this.headerMap.get(name);
	}

	public Enumeration<String> getHeaders(String name) {
		return null;
	}

	public Enumeration<String> getHeaderNames() {
		Set<String> names = new HashSet<String>();

		names.addAll(headerMap.keySet());

		return Collections.enumeration(names);
	}

	public int getIntHeader(String name) {
		return 0;
	}

	public String getMethod() {
		return this.requestMethod;
	}

	public String getPathInfo() {
		return null;
	}

	public String getPathTranslated() {
		return null;
	}

	public String getContextPath() {
		return "/";
	}

	public String getQueryString() {
		return this.queryString;
	}

	public String getRemoteUser() {
		return null;
	}

	public boolean isUserInRole(String role) {
		return false;
	}

	public Principal getUserPrincipal() {
		return null;
	}

	public String getRequestedSessionId() {
		return null;
	}

	public String getRequestURI() {
		return this.requestURL;
	}

	public StringBuffer getRequestURL() {
		return new StringBuffer(this.requestURL);
	}

	public String getServletPath() {
		return requestURL;
	}

	/**
	 * 获取Session对象
	 *
	 * @param create 是否创建Session
	 * @return HttpSession
	 */
	public HttpSession getSession(boolean create) {
		if (create) {
			return getSession();
		}

		return null;
	}

	public HttpSession getSession() {
		if (cookieMap.containsKey(SESSION_ID_NAME)) {
			String sessionID = cookieMap.get(SESSION_ID_NAME);

			return sessionMap.get(sessionID);
		}

		// 随机生成一个SessionID
		String sessionID = StringUtils.getUUID();

		return sessionMap.put(sessionID, new BinCatSession(sessionID));
	}

	public boolean isRequestedSessionIdValid() {
		return false;
	}

	public boolean isRequestedSessionIdFromCookie() {
		return false;
	}

	public boolean isRequestedSessionIdFromURL() {
		return false;
	}

	public boolean isRequestedSessionIdFromUrl() {
		return false;
	}

	public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
		return false;
	}

	public void login(String username, String password) throws ServletException {

	}

	public void logout() throws ServletException {

	}

	public Collection<Part> getParts() throws IOException, ServletException {
		return null;
	}

	public Part getPart(String name) throws IOException, ServletException {
		return null;
	}

	public Object getAttribute(String name) {
		return attributeMap.get(name);
	}

	public Enumeration<String> getAttributeNames() {
		return Collections.enumeration(attributeMap.keySet());
	}

	public String getCharacterEncoding() {
		return this.characterEncoding;
	}

	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
		this.characterEncoding = env;
	}

	public int getContentLength() {
		return 0;
	}

	public String getContentType() {
		return this.contentType;
	}

	public ServletInputStream getInputStream() throws IOException {
		return new ServletInputStream() {
			@Override
			public int read() throws IOException {
				return socketInputStream.read();
			}
		};
	}

	public String getParameter(String name) {
		if (!parsedParameter) {
			this.parseParameter();
		}

		if (parameterMap.containsKey(name)) {
			return this.parameterMap.get(name)[0];
		}

		return null;
	}

	public Enumeration<String> getParameterNames() {
		if (!parsedParameter) {
			this.parseParameter();
		}

		Set<String> names = new HashSet<String>();

		names.addAll(parameterMap.keySet());

		return Collections.enumeration(names);
	}

	public String[] getParameterValues(String name) {
		if (!parsedParameter) {
			this.parseParameter();
		}

		if (parameterMap.containsKey(name)) {
			return this.parameterMap.get(name);
		}

		return null;
	}

	public Map<String, String[]> getParameterMap() {
		if (!parsedParameter) {
			this.parseParameter();
		}

		return this.parameterMap;
	}

	public String getProtocol() {
		return this.httpVersion;
	}

	public String getScheme() {
		return "http";
	}

	public String getServerName() {
		return this.host;
	}

	public int getServerPort() {
		return this.port;
	}

	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.socketInputStream));
	}

	public String getRemoteAddr() {
		return clientSocket.getInetAddress().getHostAddress();
	}

	public String getRemoteHost() {
		return null;
	}

	public void setAttribute(String name, Object o) {
		attributeMap.put(name, o);
	}

	public void removeAttribute(String name) {
		attributeMap.remove(name);
	}

	public Locale getLocale() {
		return null;
	}

	public Enumeration<Locale> getLocales() {
		return null;
	}

	public boolean isSecure() {
		return false;
	}

	public RequestDispatcher getRequestDispatcher(String path) {
		return null;
	}

	public String getRealPath(String path) {
		return getServletContext().getRealPath(path);
	}

	public int getRemotePort() {
		return 0;
	}

	public String getLocalName() {
		return null;
	}

	public String getLocalAddr() {
		return null;
	}

	public int getLocalPort() {
		return 0;
	}

	public ServletContext getServletContext() {
		return this.servletContext;
	}

	public AsyncContext startAsync() throws IllegalStateException {
		return null;
	}

	public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
		return null;
	}

	public boolean isAsyncStarted() {
		return false;
	}

	public boolean isAsyncSupported() {
		return false;
	}

	public AsyncContext getAsyncContext() {
		return null;
	}

	public DispatcherType getDispatcherType() {
		return null;
	}

}
