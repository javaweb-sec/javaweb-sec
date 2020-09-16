package com.anbai.sec.blog.repository;

import com.anbai.sec.blog.entity.SysConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author yz
 */
@Repository
public interface SysConfigRepository extends JpaRepository<SysConfig, Long> {

}
