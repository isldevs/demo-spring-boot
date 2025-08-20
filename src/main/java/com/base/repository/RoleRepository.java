package com.base.repository;


import com.base.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author YISivlay
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
}
