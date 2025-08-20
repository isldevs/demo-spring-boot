package com.base.repository;


import com.base.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author YISivlay
 */
@Repository
public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
