package cn.emam.security.service;

import cn.emam.security.entity.RoleEntity;
import cn.emam.security.entity.RolePermissionMapper;
import cn.emam.security.entity.UserEntity;
import cn.emam.security.mapper.PermissionMapper;
import cn.emam.security.repo.RoleRepository;
import cn.emam.security.repo.UserRepository;
import cn.emam.security.repo.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Set;


/**
 * Service 层需要实现 UserDetailsService 接口，该接口是根据用户名获取该用户的所有信息， 包括用户信息和权限点。
 * @author LiQiuShui
 */
@Service
public class MyUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private UserRoleRepository userRoleRepository;
    private PermissionMapper permissionMapper;

    @Autowired
    public void setPermissionMapper(PermissionMapper permissionMapper) {
        this.permissionMapper = permissionMapper;
    }

    @Autowired
    public void setUserRoleRepository(UserRoleRepository userRoleRepository) {
        this.userRoleRepository = userRoleRepository;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    public void setRoleRepository(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(userName);
        if (user != null) {
            Set<Long> roleIds = userRoleRepository.getRoleIdByUserId(user.getId());
            List<RoleEntity> roles = roleRepository.getByIdIn(roleIds);
            user.setAuthorities(roles);
        }
        return user;
    }

    public void getRoles() {
        List<RolePermissionMapper> list = permissionMapper.getRolePermissions();
        System.out.println(list);
        //System.out.println(lists);
    }
}
