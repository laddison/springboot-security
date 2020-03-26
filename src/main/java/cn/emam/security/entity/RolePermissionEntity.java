package cn.emam.security.entity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

/**
 * 角色权限关系表
 * @author LiQiuShui
 */
@Entity
@Table(name = "role_permission")
@Data
public class RolePermissionEntity implements Serializable {
    private static final long serialVersionUID = -6640118665357910493L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_id")
    private Long roleId;

    @Column(name = "permission_id")
    private Long permissionId;
}
