package com.anbai.sec.test.springboot.directive;

import com.anbai.sec.test.springboot.commons.SpringContext;
import com.anbai.sec.test.springboot.entity.SysLinks;
import com.anbai.sec.test.springboot.service.SysLinksService;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SysLinksDirective implements TemplateDirectiveModel {

	private static final Logger LOG = LoggerFactory.getLogger(SysLinksDirective.class);

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body) {
		try {
			SysLinksService            sysLinksService = SpringContext.getBean("sysLinksServiceImpl");
			Map<String, TemplateModel> paramsMap       = new HashMap<String, TemplateModel>();

			List<SysLinks> links = sysLinksService.findAll();

			if (links != null) {
				paramsMap.put("links", DirectiveUtils.getDefaultObjectWrapper().wrap(links));
				Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
				body.render(env.getOut());

				DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
			}
		} catch (Exception e) {
			LOG.info("友情链接标签初始化异常:" + e, e);
		}
	}

}
