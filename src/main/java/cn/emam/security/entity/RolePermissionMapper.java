package cn.emam.security.entity;

import lombok.Data;
import org.springframework.stereotype.Component;

/**
 * 角色权限关系表
 * @author LiQiuShui
 */
@Data
@Component
public class RolePermissionMapper {
    private String url;
    private String roleName;
}
