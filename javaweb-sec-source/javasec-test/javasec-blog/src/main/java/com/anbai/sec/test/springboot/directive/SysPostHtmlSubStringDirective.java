package com.anbai.sec.test.springboot.directive;

import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateException;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;
import org.javaweb.utils.HttpServletRequestUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.util.Map;

public class SysPostHtmlSubStringDirective implements TemplateDirectiveModel {

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars,
	                    TemplateDirectiveBody body) throws TemplateException, IOException {

		String content = DirectiveUtils.getString("content", params);
		int    maxLen  = DirectiveUtils.getInt("maxLen", params);

		if (content != null) {
			Document document = Jsoup.parse(content);
			content = HttpServletRequestUtils.htmlSpecialChars(document.text());

			if (content != null && content.length() > 0) {
				int len = content.length() > maxLen ? maxLen : content.length();
				env.getOut().append(content.substring(0, len));
			}
		}
	}

}
