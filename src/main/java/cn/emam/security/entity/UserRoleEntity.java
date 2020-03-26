package cn.emam.security.entity;

import lombok.Data;

import javax.persistence.*;

/**
 * 用户角色关系表
 * @author LiQiuShui
 */
@Entity
@Table(name = "user_role")
@Data
public class UserRoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private  Integer id;
    @Column(name = "user_id")
    private Long userId;
    @Column(name = "role_id")
    private Long roleId;
}
