# springboot-security
springboot-security learning

## 简介
Spring Security，这是一种基于 Spring AOP 和 Servlet 过滤器的安全框架。它提供全面的安全性解决方案，同时在 Web 请求级和方法调用级处理身份确认和授权。

## 快速上手
### 建表
```
建表语句
DROP TABLE IF EXISTS `user`;
DROP TABLE IF EXISTS `role`;
DROP TABLE IF EXISTS `user_role`;
DROP TABLE IF EXISTS `role_permission`;
DROP TABLE IF EXISTS `permission`;

CREATE TABLE `user` (
`id` bigint(11) NOT NULL AUTO_INCREMENT,
`username` varchar(255) NOT NULL,
`password` varchar(255) NOT NULL,
PRIMARY KEY (`id`) 
);
CREATE TABLE `role` (
`id` bigint(11) NOT NULL AUTO_INCREMENT,
`name` varchar(255) NOT NULL,
PRIMARY KEY (`id`) 
);
CREATE TABLE `user_role` (
`user_id` bigint(11) NOT NULL,
`role_id` bigint(11) NOT NULL
);
CREATE TABLE `role_permission` (
`role_id` bigint(11) NOT NULL,
`permission_id` bigint(11) NOT NULL
);
CREATE TABLE `permission` (
`id` bigint(11) NOT NULL AUTO_INCREMENT,
`url` varchar(255) NOT NULL,
`name` varchar(255) NOT NULL,
`description` varchar(255) NULL,
`pid` bigint(11) NOT NULL,
PRIMARY KEY (`id`) 
);

INSERT INTO user (id, username, password) VALUES (1,'user','e10adc3949ba59abbe56e057f20f883e'); 
INSERT INTO user (id, username , password) VALUES (2,'admin','e10adc3949ba59abbe56e057f20f883e'); 
INSERT INTO role (id, name) VALUES (1,'USER');
INSERT INTO role (id, name) VALUES (2,'ADMIN');
INSERT INTO permission (id, url, name, pid) VALUES (1,'/user/common','common',0);
INSERT INTO permission (id, url, name, pid) VALUES (2,'/user/admin','admin',0);
INSERT INTO user_role (user_id, role_id) VALUES (1, 1);
INSERT INTO user_role (user_id, role_id) VALUES (2, 1);
INSERT INTO user_role (user_id, role_id) VALUES (2, 2);
INSERT INTO role_permission (role_id, permission_id) VALUES (1, 1);
INSERT INTO role_permission (role_id, permission_id) VALUES (2, 1);
INSERT INTO role_permission (role_id, permission_id) VALUES (2, 2);
```
### pom.xml
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-security4</artifactId>
</dependency>

```

### application.yml
```
spring:
  thymeleaf:
    mode: HTML5
    encoding: UTF-8
    cache: false

  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/spring-security?useUnicode=true&characterEncoding=utf-8&useSSL=false
    username: root
    password: root
```
### User
```
public class User implements UserDetails , Serializable {

    private Long id;
    private String username;
    private String password;

    private List<Role> authorities;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public List<Role> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Role> authorities) {
        this.authorities = authorities;
    }

    /**
     * 用户账号是否过期
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 用户账号是否被锁定
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 用户密码是否过期
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 用户是否可用
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
    
}
```
上面的 User 类实现了 UserDetails 接口，该接口是实现Spring Security 认证信息的核心接口。其中 getUsername 方法为 UserDetails 接口 的方法，这个方法返回 username，也可以是其他的用户信息，例如手机号、邮箱等。getAuthorities() 方法返回的是该用户设置的权限信息，在本实例中，模拟从数据库取出用户的所有角色信息，权限信息也可以是用户的其他信息，不一定是角色信息。另外需要读取密码，最后几个方法一般情况下都返回 true，也可以根据自己的需求进行业务判断。
### Role
```
public class Role implements GrantedAuthority {

    private Long id;
    private String name;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getAuthority() {
        return name;
    }

}
```
Role 类实现了 GrantedAuthority 接口，并重写 getAuthority() 方法。权限点可以为任何字符串，不一定是非要用角色名。
所有的Authentication实现类都保存了一个GrantedAuthority列表，其表示用户所具有的权限。GrantedAuthority是通过AuthenticationManager设置到Authentication对象中的，然后AccessDecisionManager将从Authentication中获取用户所具有的GrantedAuthority来鉴定用户是否具有访问对应资源的权限。
### MyUserDetailsService
```
@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;
    @Autowired
    private RoleMapper roleMapper;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        //查数据库
        User user = userMapper.loadUserByUsername( userName );
        if (null != user) {
            List<Role> roles = roleMapper.getRolesByUserId( user.getId() );
            user.setAuthorities( roles );
        }

        return user;
    }
    

}
```
Service 层需要实现 UserDetailsService 接口，该接口是根据用户名获取该用户的所有信息， 包括用户信息和权限点。
### MyInvocationSecurityMetadataSourceService
```
@Component
public class MyInvocationSecurityMetadataSourceService implements FilterInvocationSecurityMetadataSource {

    @Autowired
    private PermissionMapper permissionMapper;

    /**
     * 每一个资源所需要的角色 Collection<ConfigAttribute>决策器会用到
     */
    private static HashMap<String, Collection<ConfigAttribute>> map =null;


    /**
     * 返回请求的资源需要的角色
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        if (null == map) {
            loadResourceDefine();
        }
        //object 中包含用户请求的request 信息
        HttpServletRequest request = ((FilterInvocation) o).getHttpRequest();
        for (Iterator<String> it = map.keySet().iterator() ; it.hasNext();) {
            String url = it.next();
            if (new AntPathRequestMatcher( url ).matches( request )) {
                return map.get( url );
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }

    /**
     * 初始化 所有资源 对应的角色
     */
    public void loadResourceDefine() {
        map = new HashMap<>(16);
        //权限资源 和 角色对应的表  也就是 角色权限 中间表
        List<RolePermisson> rolePermissons = permissionMapper.getRolePermissions();

        //某个资源 可以被哪些角色访问
        for (RolePermisson rolePermisson : rolePermissons) {

            String url = rolePermisson.getUrl();
            String roleName = rolePermisson.getRoleName();
            ConfigAttribute role = new SecurityConfig(roleName);

            if(map.containsKey(url)){
                map.get(url).add(role);
            }else{
                List<ConfigAttribute> list =  new ArrayList<>();
                list.add( role );
                map.put( url , list );
            }
        }
    }


}
```
MyInvocationSecurityMetadataSourceService 类实现了 FilterInvocationSecurityMetadataSource，FilterInvocationSecurityMetadataSource 的作用是用来储存请求与权限的对应关系。
FilterInvocationSecurityMetadataSource接口有3个方法：  

boolean supports(Class<?> clazz)：指示该类是否能够为指定的方法调用或Web请求提供ConfigAttributes。  
Collection getAllConfigAttributes()：Spring容器启动时自动调用,  一般把所有请求与权限的对应关系也要在这个方法里初始化, 保存在一个属性变量里。  
Collection getAttributes(Object object)：当接收到一个http请求时, filterSecurityInterceptor会调用的方法. 参数object是一个包含url信息的HttpServletRequest实例. 这个方法要返回请求该url所需要的所有权限集合。  

###MyAccessDecisionManager
```
/**
 * 决策器
 */
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {

    private final static Logger logger = LoggerFactory.getLogger(MyAccessDecisionManager.class);

    /**
     * 通过传递的参数来决定用户是否有访问对应受保护对象的权限
     *
     * @param authentication 包含了当前的用户信息，包括拥有的权限。这里的权限来源就是前面登录时UserDetailsService中设置的authorities。
     * @param object  就是FilterInvocation对象，可以得到request等web资源
     * @param configAttributes configAttributes是本次访问需要的权限
     */
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

    /**
     * 表示此AccessDecisionManager是否能够处理传递的ConfigAttribute呈现的授权请求
     */
    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    /**
     * 表示当前AccessDecisionManager实现是否能够为指定的安全对象（方法调用或Web请求）提供访问控制决策
     */
    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }

}
```
MyAccessDecisionManager 类实现了AccessDecisionManager接口，AccessDecisionManager是由AbstractSecurityInterceptor调用的，它负责鉴定用户是否有访问对应资源（方法或URL）的权限。
### MyFilterSecurityInterceptor
```
@Component
public class MyFilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {


    @Autowired
    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Autowired
    public void setMyAccessDecisionManager(MyAccessDecisionManager myAccessDecisionManager) {
        super.setAccessDecisionManager(myAccessDecisionManager);
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);
        invoke(fi);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {

        InterceptorStatusToken token = super.beforeInvocation(fi);
        try {
            //执行下一个拦截器
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } finally {
            super.afterInvocation(token, null);
        }
    }

    @Override
    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {

        return this.securityMetadataSource;
    }
    
    
}
```
每种受支持的安全对象类型（方法调用或Web请求）都有自己的拦截器类，它是AbstractSecurityInterceptor的子类，AbstractSecurityInterceptor 是一个实现了对受保护对象的访问进行拦截的抽象类。
AbstractSecurityInterceptor的机制可以分为几个步骤：  

查找与当前请求关联的“配置属性（简单的理解就是权限）”  

将 安全对象（方法调用或Web请求）、当前身份验证、配置属性 提交给决策器（AccessDecisionManager）

（可选）更改调用所根据的身份验证

允许继续进行安全对象调用(假设授予了访问权)

在调用返回之后，如果配置了AfterInvocationManager。如果调用引发异常，则不会调用AfterInvocationManager。

AbstractSecurityInterceptor中的方法说明：

beforeInvocation()方法实现了对访问受保护对象的权限校验，内部用到了AccessDecisionManager和AuthenticationManager；
finallyInvocation()方法用于实现受保护对象请求完毕后的一些清理工作，主要是如果在beforeInvocation()中改变了SecurityContext，则在finallyInvocation()中需要将其恢复为原来的SecurityContext，该方法的调用应当包含在子类请求受保护资源时的finally语句块中。
afterInvocation()方法实现了对返回结果的处理，在注入了AfterInvocationManager的情况下默认会调用其decide()方法。

了解了AbstractSecurityInterceptor，就应该明白了，我们自定义MyFilterSecurityInterceptor就是想使用我们之前自定义的 AccessDecisionManager 和 securityMetadataSource。
### SecurityConfig
@EnableWebSecurity注解以及WebSecurityConfigurerAdapter一起配合提供基于web的security。自定义类 继承了WebSecurityConfigurerAdapter来重写了一些方法来指定一些特定的Web安全设置。
```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService userService;


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

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
            public boolean matches(CharSequence charSequence, String s) {
                String encode = DigestUtils.md5DigestAsHex(charSequence.toString().getBytes());
                boolean res = s.equals( encode );
                return res;
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
```
### MainController
```
@Controller
public class MainController {

    @RequestMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @RequestMapping("/index")
    public String index() {
        return "index";
    }

    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping("/login-error")
    public String loginError(Model model) {
        model.addAttribute( "loginError"  , true);
        return "login";
    }

    @GetMapping("/401")
    public String accessDenied() {
        return "401";
    }

    @GetMapping("/user/common")
    public String common() {
        return "user/common";
    }

    @GetMapping("/user/admin")
    public String admin() {
        return "user/admin";
    }


}
```
### 页面

login.html
```
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>
<body>
    <h1>Login page</h1>
    <p th:if="${loginError}" class="error">用户名或密码错误</p>
    <form th:action="@{/login}" method="post">
        <label for="username">用户名</label>:
        <input type="text" id="username" name="username" autofocus="autofocus" />
        <br/>
        <label for="password">密  码</label>:
        <input type="password" id="password" name="password" />
        <br/>
        <input type="submit" value="登录" />
    </form>
    <p><a href="/index" th:href="@{/index}"></a></p>
</body>
</html>
```
index.html
```
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
<head>
    <meta charset="UTF-8">
    <title>首页</title>
</head>
<body>
    <h2>page list</h2>
    <a href="/user/common">common page</a>
    <br/>
    <a href="/user/admin">admin page</a>
    <br/>
    <form th:action="@{/logout}" method="post">
        <input type="submit" class="btn btn-primary" value="注销"/>
    </form>
</body>
</html>
```
admin.html
```
<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>admin page</title>
</head>
<body>
    success admin page！！！
</body>
</html>
```
common.html
```
<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>common page</title>
</head>
<body>
    success common page！！！
</body>
</html>
```
401.html
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>401 page</title>
</head>
<body>
    <div>
        <div>
            <h2>权限不够</h2>
            <p>拒绝访问！</p>
        </div>
    </div>
</body>
</html>
```
最后运行项目，可以分别用 user、admin 账号 去测试认证和授权是否正确。



