package com.anbai.sec.test.springboot.directive;

import com.anbai.sec.test.springboot.commons.SpringContext;
import com.anbai.sec.test.springboot.service.SysConfigService;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class SysConfigDirective implements TemplateDirectiveModel {

	private static final Logger LOG = LoggerFactory.getLogger(SysConfigDirective.class);

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body) {
		try {
			SysConfigService    sysConfigService = SpringContext.getBean("sysConfigServiceImpl");
			Map<String, Object> configMap        = sysConfigService.getSysConfig();

			if (configMap != null) {
				Map<String, TemplateModel> paramsMap = new HashMap<>();

				for (String key : configMap.keySet()) {
					paramsMap.put(key, DirectiveUtils.getDefaultObjectWrapper().wrap(configMap.get(key)));
				}

				Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
				body.render(env.getOut());
				DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
			}
		} catch (Exception e) {
			LOG.info("系统配置标签加载异常:" + e, e);
		}
	}

}