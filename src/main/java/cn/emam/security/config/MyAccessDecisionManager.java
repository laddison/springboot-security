package cn.emam.security.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Iterator;

/**
 * 负责鉴定用户是否有访问对应资源（方法或URL）的权限
 * @author LiQiuShui
 */
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        if (null == configAttributes || 0 >= configAttributes.size()) {
            return;
        } else {
            String needRole;
            for(Iterator<ConfigAttribute> iter = configAttributes.iterator(); iter.hasNext(); ) {
                needRole = iter.next().getAttribute();

                for(GrantedAuthority ga : authentication.getAuthorities()) {
                    if(needRole.trim().equals(ga.getAuthority().trim())) {
                        return;
                    }
                }
            }
            throw new AccessDeniedException("当前访问没有权限");
        }
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
