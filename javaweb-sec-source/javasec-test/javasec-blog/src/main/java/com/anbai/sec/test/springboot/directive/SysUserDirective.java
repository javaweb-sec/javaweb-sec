/*
 * Copyright yz 2016-2-19 Email:admin@javaweb.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.anbai.sec.test.springboot.directive;

import com.anbai.sec.test.springboot.commons.SpringContext;
import com.anbai.sec.test.springboot.entity.SysUser;
import com.anbai.sec.test.springboot.service.SysUserService;
import freemarker.core.Environment;
import freemarker.template.TemplateDirectiveBody;
import freemarker.template.TemplateDirectiveModel;
import freemarker.template.TemplateException;
import freemarker.template.TemplateModel;
import org.javaweb.utils.DirectiveUtils;
import org.javaweb.utils.EncryptUtils;
import org.javaweb.utils.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 用户相关的自定义标签
 *
 * @author yz
 */
public abstract class SysUserDirective implements TemplateDirectiveModel {

	public abstract void execute(Environment env, Map params,
	                             TemplateModel[] loopVars, TemplateDirectiveBody body,
	                             SysUser sysUser) throws TemplateException, IOException;

	@Override
	public void execute(Environment env, Map params, TemplateModel[] loopVars,
	                    TemplateDirectiveBody body) throws TemplateException, IOException {

		SysUser sysUser = DirectiveUtils.paramsMap2Bean(params, SysUser.class);
		execute(env, params, loopVars, body, sysUser);
	}

	/**
	 * 输出用户gravatar头像URL地址
	 */
	public static class GravatarUrlDirective extends SysUserDirective implements
			TemplateDirectiveModel {

		@Override
		public void execute(Environment env, Map params, TemplateModel[] loopVars, TemplateDirectiveBody body, SysUser sysUser) throws TemplateException, IOException {
			String email = DirectiveUtils.getString("email", params);
			String size  = DirectiveUtils.getString("size", params);

			if (StringUtils.isEmpty(size)) {
				size = "80";
			}

			env.getOut().append("https://cn.gravatar.com/avatar/" + EncryptUtils.md5(email) + "?s=" + size);
		}

	}

	/**
	 * 获取任意用户信息,这个标签需要谨慎使用
	 *
	 * @author yz
	 */
	public static class SysUserInfoDirective extends SysUserDirective implements
			TemplateDirectiveModel {

		@Override
		public void execute(Environment env, Map params,
		                    TemplateModel[] loopVars, TemplateDirectiveBody body,
		                    SysUser sysUser) throws TemplateException, IOException {

			SysUserService sysUserService = SpringContext.getBean("sysUserServiceImpl");
			sysUser = sysUserService.getSysUserById(sysUser.getUserId());

			if (sysUser != null) {
				Map<String, TemplateModel> paramsMap = new HashMap<String, TemplateModel>();
				paramsMap.put("jw_user", DirectiveUtils.getDefaultObjectWrapper().wrap(sysUser));
				Map<String, TemplateModel> origMap = DirectiveUtils.addParamsToVariable(env, paramsMap);
				body.render(env.getOut());

				DirectiveUtils.removeParamsFromVariable(env, paramsMap, origMap);
			}
		}

	}

}
