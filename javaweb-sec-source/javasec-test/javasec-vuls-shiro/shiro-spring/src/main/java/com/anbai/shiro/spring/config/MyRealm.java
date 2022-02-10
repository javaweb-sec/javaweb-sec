package com.anbai.shiro.spring.config;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

/**
 * @author su18
 */
//@Component("authorizer")
public class MyRealm extends AuthorizingRealm {


	/**
	 * 用户登陆认证
	 *
	 * @param token AuthenticationToken
	 * @return AuthenticationInfo
	 * @throws AuthenticationException 抛出异常
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		UsernamePasswordToken authToken = (UsernamePasswordToken) token;

		if ("admin".equals(authToken.getUsername())) {
			return new SimpleAuthenticationInfo("admin", "admin", this.getName());
		}
		if ("auditor".equals(authToken.getUsername())) {
			return new SimpleAuthenticationInfo("auditor", "auditor", this.getName());
		}
		if ("normal".equals(authToken.getUsername())) {
			return new SimpleAuthenticationInfo("user", "user", this.getName());
		}
		return null;
	}

	/**
	 * 用户授权
	 * 本示例用户角色包括两个 user admin
	 * 本示例权限分为三种，user admin auditor
	 *
	 * @param principals PrincipalCollection
	 * @return 返回 AuthenticationInfo
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

		String                  currentUsername  = (String) super.getAvailablePrincipal(principals);
		SimpleAuthorizationInfo simpleAuthorInfo = new SimpleAuthorizationInfo();

		if ("admin".equals(currentUsername)) {
			simpleAuthorInfo.addRole("admin");
			simpleAuthorInfo.addStringPermission("admin");
			return simpleAuthorInfo;
		}

		if ("auditor".equals(currentUsername)) {
			simpleAuthorInfo.addRole("auditor");
			simpleAuthorInfo.addStringPermission("audit:list");
			return simpleAuthorInfo;
		}

		if ("user".equals(currentUsername)) {
			return simpleAuthorInfo;
		}

		return null;
	}
}

