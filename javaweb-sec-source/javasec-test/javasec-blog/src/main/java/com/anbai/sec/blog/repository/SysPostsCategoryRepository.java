package com.anbai.sec.blog.repository;

import com.anbai.sec.blog.entity.SysPostsCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author yz
 */
@Repository
public interface SysPostsCategoryRepository extends JpaRepository<SysPostsCategory, Integer> {

	List<SysPostsCategory> findByParentIdOrderByCategoryOrder(Integer parentId);

	List<SysPostsCategory> findByParentIdNotOrderByCategoryOrderAsc(Integer parentId);

}
