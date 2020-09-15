package com.anbai.sec.test.springboot.service;

import com.anbai.sec.test.springboot.entity.SysUser;

/**
 * @author yz
 */
public interface SysUserService {

	SysUser getSysUserById(Integer userId);

	SysUser setUser(SysUser user);

}
