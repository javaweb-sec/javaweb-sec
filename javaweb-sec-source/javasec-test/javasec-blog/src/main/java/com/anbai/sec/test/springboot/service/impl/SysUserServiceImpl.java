package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.entity.SysUser;
import com.anbai.sec.test.springboot.repository.SysUserRepository;
import com.anbai.sec.test.springboot.service.SysUserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * @author yz
 */
@Service
public class SysUserServiceImpl implements SysUserService {

	@Resource
	private SysUserRepository sysUserRepository;

	@Override
	public SysUser getSysUserById(Integer userId) {
		return sysUserRepository.getOne(userId);
	}

	@Override
	public SysUser setUser(SysUser user) {
		SysUser u = sysUserRepository.getOne(user.getUserId());

		u.setNick(user.getNick());
		u.setUsername(user.getUsername());


		return sysUserRepository.save(user);
	}

}
