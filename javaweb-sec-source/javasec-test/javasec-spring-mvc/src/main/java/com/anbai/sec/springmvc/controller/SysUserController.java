package com.anbai.sec.springmvc.controller;

import com.anbai.sec.springmvc.commons.ResultInfo;
import com.anbai.sec.springmvc.entity.SysUser;
import com.anbai.sec.springmvc.repository.SysUserRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

import static org.javaweb.utils.StringUtils.isNotEmpty;

@RestController
public class SysUserController {

	@Resource
	private SysUserRepository sysUserRepository;

	@PostMapping(value = "/login.do")
	public ResultInfo<SysUser> login(@RequestBody SysUser user) {
		ResultInfo<SysUser> result = new ResultInfo<>();

		if (isNotEmpty(user.getUsername()) && isNotEmpty(user.getPassword())) {
			SysUser sysUser = sysUserRepository.findByUsernameAndAndPassword(user.getUsername(), user.getPassword());

			if (sysUser != null) {
				result.setData(sysUser);
				result.setValid(true);
			} else {
				result.setMsg("登陆失败，账号或密码错误!");
			}
		} else {
			result.setMsg("请求参数错误!");
		}

		return result;
	}

}