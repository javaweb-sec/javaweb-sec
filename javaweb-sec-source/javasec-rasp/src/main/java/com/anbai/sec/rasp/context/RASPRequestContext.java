package com.anbai.sec.rasp.context;

import com.anbai.sec.rasp.servlet.http.RASPFilterChain;
import com.anbai.sec.rasp.servlet.http.RASPHttpRequest;
import com.anbai.sec.rasp.servlet.http.RASPHttpResponse;

public class RASPRequestContext {

	private final RASPHttpRequest servletRequest;

	private final RASPHttpResponse servletResponse;

	private final Object cacheClass;

	private final RASPFilterChain filterChain;

	public RASPRequestContext(RASPHttpRequest req, RASPHttpResponse resp, RASPFilterChain chain, Object cacheClass) {
		this.servletRequest = req;
		this.servletResponse = resp;
		this.cacheClass = cacheClass;
		this.filterChain = chain;
	}

	public RASPHttpRequest getServletRequest() {
		return servletRequest;
	}

	public RASPHttpResponse getServletResponse() {
		return servletResponse;
	}

	public Object getCacheClass() {
		return cacheClass;
	}

	public RASPFilterChain getFilterChain() {
		return filterChain;
	}

}
