package cn.emam.security.repo;

import cn.emam.security.entity.RolePermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 角色权限
 * @author LiQiuShui
 */
public interface RolePermissionRepository extends JpaRepository<RolePermissionEntity, Long> {
}
