package cn.emam.security.repo;

import cn.emam.security.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 用户Repo
 * @author LiQiuShui
 */
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    /**
     * 根据用户名称查找
     * @param username 用户名
     * @return UserEntity
     */
    UserEntity findByUsername(String username);
}
