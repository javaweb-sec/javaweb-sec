package com.anbai.sec.blog.repository;

import com.anbai.sec.blog.entity.SysLinks;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

/**
 * @author yz
 */
@Repository
public interface SysLinksRepository extends JpaRepository<SysLinks, Integer>,
		PagingAndSortingRepository<SysLinks, Integer>, JpaSpecificationExecutor<SysLinks> {


}
