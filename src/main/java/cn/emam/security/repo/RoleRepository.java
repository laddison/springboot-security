package cn.emam.security.repo;

import cn.emam.security.entity.PermissionEntity;
import cn.emam.security.entity.RoleEntity;
import cn.emam.security.entity.RolePermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Set;

/**
 * 角色repo
 * @author LiQiuShui
 */
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    /**
     * 通过roleId 获取role列表
     * @param roleId id
     * @return List
     */
    List<RoleEntity> getByIdIn(Set<Long> roleId);

    @Query("select R.name from RoleEntity R Left Join RolePermissionEntity as RP On R.id = RP.roleId")
    List<RolePermissionEntity> getRolePermissions();
}
