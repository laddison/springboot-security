package cn.emam.security.repo;

import cn.emam.security.entity.UserRoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Set;

/**
 * 用户角色关系表
 * @author LiQiuShui
 */
public interface UserRoleRepository extends JpaRepository<UserRoleEntity, Integer> {
    /**
     * 根据用户id查找列表
     * @param userId
     * @return
     */
    List<UserRoleEntity> getAllByUserId(Long userId);

    /**
     * 通过用户id获取角色id
     * @param userId 用户id
     * @return Set<Long>
     */
    @Query("select roleId from UserRoleEntity where userId = :userId ")
    Set<Long> getRoleIdByUserId(@Param("userId") Long userId);
}
