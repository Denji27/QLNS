package net.example.springboot.Repository;

import net.example.springboot.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    public Role findRoleByRoleId(long roleId);
}
