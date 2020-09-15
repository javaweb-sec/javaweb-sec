package com.anbai.sec.test.springboot.repository;

import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author yz
 */
@Repository
public interface SysPostsCategoryRepository extends JpaRepository<SysPostsCategory, Integer> {

	List<SysPostsCategory> findByParentIdOrderByCategoryOrder(Integer parentId);

}
