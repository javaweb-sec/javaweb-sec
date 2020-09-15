package com.anbai.sec.test.springboot.directive;

import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.commons.SpringContext;
import com.anbai.sec.test.springboot.entity.SysComments;
import com.anbai.sec.test.springboot.service.SysCommentService;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;

import java.util.HashMap;
import java.util.Map;

public class SysCommentsDirective implements TemplateDirectiveModel {

	private static final Logger LOG = LoggerFactory.getLogger(SysCommentsDirective.class);

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body) {
		try {
			SysCommentService          sysCommentService = SpringContext.getBean("sysCommentServiceImpl");
			Map<String, TemplateModel> paramsMap         = new HashMap<String, TemplateModel>();
			SysComments                sysComments       = new SysComments();
			SearchCondition            condition         = new SearchCondition();
			Page<SysComments>          comments          = sysCommentService.search(sysComments, condition);

			if (comments != null) {
				paramsMap.put("comments", DirectiveUtils.getDefaultObjectWrapper().wrap(comments));
				Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
				body.render(env.getOut());

				DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
			}
		} catch (Exception e) {
			LOG.info("友情链接标签初始化异常:" + e, e);
		}
	}

}
