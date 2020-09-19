package com.anbai.sec.springmvc.repository;

import com.anbai.sec.springmvc.entity.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author yz
 */
@Repository
public interface SysUserRepository extends JpaRepository<SysUser, Integer> {

	SysUser findByUsernameAndAndPassword(String username, String password);

}
