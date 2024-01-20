package xyz.pplax.oauth.authcode.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableResourceServer
public class ResourceConfig extends ResourceServerConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Primary
    @Bean
    public RemoteTokenServices remoteTokenServices() {
        final RemoteTokenServices tokenServices = new RemoteTokenServices();
        //设置授权服务器check_token端点完整地址
        tokenServices.setCheckTokenEndpointUrl("http://localhost:8080/oauth/check_token");
        //设置客户端id与secret，注意：client_secret值不能使用passwordEncoder加密！
        tokenServices.setClientId("client-a");
        tokenServices.setClientSecret("client-a-secret");
        return tokenServices;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 登录成功处理类
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        //设置创建session策略
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        //@formatter:off
        //所有请求必须授权
        http.authorizeRequests()
                //静态文件允许访问
                .antMatchers().permitAll()
                // 放行
                .antMatchers( "/assets/**","/login","/test/**","/testfather/**","/testes/**","/advice/**","css/**","/js/**","/image/*").permitAll()
                //其他所有请求需要登录, anyRequest 不能配置在 antMatchers 前面
                .anyRequest().authenticated()
                .and()
                //登录页面配置，用于替换security默认页面
                .formLogin().loginPage(  "/login").successHandler(successHandler).and()
                //登出页面配置，用于替换security默认页面
                .logout().logoutUrl( "/logout").and()
                .httpBasic().and()
                // 开启了csrf防御 如果要放行/test/** 还需要在下面ignoringAntMatchers进行配置
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // 这里还需要放行 当然如果是 .csrf().disable()就不会有这个问题了
                .ignoringAntMatchers(
                        "/instances",
                        "/actuator/**",
                        "/test/**",
                        "/advice/**",
                        "/testes/**"
                );
        //@formatter:on
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("resource1").stateless(true);
    }
}