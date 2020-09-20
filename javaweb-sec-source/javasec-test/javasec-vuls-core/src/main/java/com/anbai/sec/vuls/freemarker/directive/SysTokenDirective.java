package com.anbai.sec.vuls.freemarker.directive;

import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateModel;
import org.javaweb.utils.HttpServletRequestUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

public class SysTokenDirective implements TemplateDirectiveModel {

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars,
	                    TemplateDirectiveBody body) throws IOException {

		HttpServletRequest request = HttpServletRequestUtils.getCurrentHttpServletRequest();

		if (request != null) {
			// 获取token字符串
			String token = HttpServletRequestUtils.getToken(request);
			env.getOut().append(token);
		}
	}

}