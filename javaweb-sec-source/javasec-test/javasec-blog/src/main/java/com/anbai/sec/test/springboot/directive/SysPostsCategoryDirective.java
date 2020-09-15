package com.anbai.sec.test.springboot.directive;

import com.anbai.sec.test.springboot.commons.SpringContext;
import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import com.anbai.sec.test.springboot.service.SysPostsCategoryService;
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

public class SysPostsCategoryDirective implements TemplateDirectiveModel {

	private static final Logger LOG = LoggerFactory.getLogger(SysPostsCategoryDirective.class);

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body) {
		try {
			SysPostsCategoryService    categoryService = SpringContext.getBean("sysPostsCategoryServiceImpl");
			Map<String, TemplateModel> paramsMap       = new HashMap<String, TemplateModel>();

			Integer parentId = DirectiveUtils.getInt("pid", params);
			parentId = parentId != null ? parentId : 0;// 设置父ID,如果未传值默认0

			List<SysPostsCategory> categories = categoryService.getSysPostsCategoryByParentId(parentId);

			if (categories != null) {
				paramsMap.put("categories", DirectiveUtils.getDefaultObjectWrapper().wrap(categories));
				Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
				body.render(env.getOut());

				DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
			}
		} catch (Exception e) {
			LOG.info("文章分类标签初始化异常:" + e, e);
		}
	}

}
