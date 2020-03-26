package cn.emam.security.config;

import cn.emam.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

/**
 * securityConfig
 * @author LiQiuShui
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private MyUserDetailsService userService;

    @Autowired
    public void setUserDetailsService(MyUserDetailsService userService) {
        this.userService = userService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //校验用户
        auth.userDetailsService( userService ).passwordEncoder( new PasswordEncoder() {
            //对密码进行加密
            @Override
            public String encode(CharSequence charSequence) {
                System.out.println(charSequence.toString());
                return DigestUtils.md5DigestAsHex(charSequence.toString().getBytes());
            }
            //对密码进行判断匹配
            @Override
            public boolean matches(CharSequence charSequence, String str) {
                String encode = DigestUtils.md5DigestAsHex(charSequence.toString().getBytes());
                return str.equals( encode );
            }
        } );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/","index","/login","/login-error","/401","/css/**","/js/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage( "/login" ).failureUrl( "/login-error" )
                .and()
                .exceptionHandling().accessDeniedPage( "/401" );
        http.logout().logoutSuccessUrl( "/" );
    }
}
