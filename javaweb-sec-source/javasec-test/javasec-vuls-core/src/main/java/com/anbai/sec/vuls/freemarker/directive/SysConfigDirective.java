package com.anbai.sec.vuls.freemarker.directive;

import com.anbai.sec.vuls.context.SpringContext;
import com.anbai.sec.vuls.dao.SysConfigDAO;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateException;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class SysConfigDirective implements TemplateDirectiveModel {

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body)
			throws TemplateException, IOException {

		SysConfigDAO        sysConfigDAO = SpringContext.getBean("sysConfigDAO");
		Map<String, Object> configMap    = sysConfigDAO.getSysConfig();

		if (configMap != null) {
			Map<String, TemplateModel> paramsMap = new HashMap();

			for (String key : configMap.keySet()) {
				paramsMap.put(key, DirectiveUtils.getDefaultObjectWrapper().wrap(configMap.get(key)));
			}

			Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
			body.render(env.getOut());
			DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
		}
	}

}