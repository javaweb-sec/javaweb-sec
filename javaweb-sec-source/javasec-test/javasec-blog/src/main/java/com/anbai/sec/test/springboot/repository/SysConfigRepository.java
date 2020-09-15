package com.anbai.sec.test.springboot.repository;

import com.anbai.sec.test.springboot.entity.SysConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author yz
 */
@Repository
public interface SysConfigRepository extends JpaRepository<SysConfig, Long> {

}
