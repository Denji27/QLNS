package net.example.springboot.Repository;

import net.example.springboot.Model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission,Long> {
    public Permission findByPermissionName(String permissionName);
}
