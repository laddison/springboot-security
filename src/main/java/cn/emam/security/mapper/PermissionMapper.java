package cn.emam.security.mapper;

import cn.emam.security.entity.RolePermissionEntity;
import cn.emam.security.entity.RolePermissionMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 权限对应关系表
 * @author LiQiuShui
 */
@Component
@Mapper
public interface PermissionMapper {
    /**
     * 获取角色权限对应关系列表
     * @return
     */
    @Select("select A.name as roleName,C.url from role as A " +
            "left join role_permission B on A.id = B.role_id " +
            "left join permission C on B.permission_id = C.id")
    List<RolePermissionMapper> getRolePermissions();
}
