package com.anbai.sec.rasp.context;

import com.anbai.sec.rasp.servlet.http.RASPFilterChain;
import com.anbai.sec.rasp.servlet.http.RASPHttpRequest;
import com.anbai.sec.rasp.servlet.http.RASPHttpResponse;

public class RASPRequestContextManager {

	/**
	 * Http请求上下文
	 */
	private static final ThreadLocal<RASPRequestContext> REQUEST_CONTEXT = new ThreadLocal<RASPRequestContext>();

	/**
	 * 获取当前线程中的Http请求上下文
	 *
	 * @return RASPHttpRequestContext
	 */
	public static RASPRequestContext getContext() {
		return REQUEST_CONTEXT.get();
	}

	/**
	 * 设置当前线程中的Http请求上下文
	 *
	 * @param context RASPHttpRequestContext
	 */
	public static void setContext(RASPRequestContext context) {
		REQUEST_CONTEXT.set(context);
	}

	/**
	 * 设置当前线程中的Http请求上下文
	 *
	 * @param req        RASPHttpRequest
	 * @param resp       RASPHttpResponse
	 * @param chain      RASPFilterChain
	 * @param cacheClass Object
	 */
	public static void setContext(Object req, Object resp, Object chain, Object cacheClass) {
		if (getContext() != null) {
			return;
		}

		RASPHttpRequest  request     = new RASPHttpRequest(req);
		RASPHttpResponse response    = new RASPHttpResponse(resp);
		RASPFilterChain  filterChain = null;

		if (chain != null) {
			filterChain = new RASPFilterChain(chain);
		}

		REQUEST_CONTEXT.set(new RASPRequestContext(request, response, filterChain, cacheClass));
	}

	/**
	 * 检测是否包含Http请求
	 *
	 * @return 返回当前线程中是否包含了Http请求(context 、 request 、 response都不为空)
	 */
	public static boolean hasRequest() {
		RASPRequestContext context = getContext();

		if (context != null) {
			return context.getServletRequest() != null && context.getServletResponse() != null;
		}

		return false;
	}

}
