package com.anbai.sec.blog.repository;

import com.anbai.sec.blog.entity.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.Optional;

@RepositoryRestResource(path = "user")
public interface SysUserRepositoryController extends JpaRepository<SysUser, Integer> {

	@Override
	Optional<SysUser> findById(Integer id);

	SysUser findByUsername(String username);

	SysUser findByEmail(String email);

}