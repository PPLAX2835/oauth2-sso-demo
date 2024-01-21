package xyz.pplax.oauth.authcode.config;

///**
// * 这是内存存储client_id的方案
// */
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
//
////授权服务器配置
//@Configuration
//@EnableAuthorizationServer //开启授权服务
//public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//        //允许表单提交
//        security.allowFormAuthenticationForClients()
//                .checkTokenAccess("isAuthenticated()");
//    }
//
//    @Override
//    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        // @formatter: off
//        clients.inMemory()
//                .withClient("client-a") //客户端唯一标识（client_id）
//                .secret(passwordEncoder.encode("client-a-secret")) //客户端的密码(client_secret)，这里的密码应该是加密后的
//                .authorizedGrantTypes("authorization_code") //授权模式标识
//                .scopes("read_user_info") //作用域
//                .resourceIds("resource1") //资源id
//                .redirectUris("http://localhost:9001/callback") //回调地址
//
//                .and()
//                    .withClient("testClient")
//                .secret(passwordEncoder.encode("testSecret"))
//                .authorizedGrantTypes("authorization_code")
//                .scopes("test_scopes")
//                .resourceIds("test_resource")
//                .redirectUris("https://www.bilibili.com/");
//        // @formatter: on
//    }
//}

///**
// * 这是jdbc存储client_id的方案
// */
//import org.springframework.boot.context.properties.ConfigurationProperties;
//import org.springframework.boot.jdbc.DataSourceBuilder;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
//import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
//import org.springframework.security.oauth2.provider.ClientDetailsService;
//import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
//
//import javax.sql.DataSource;
//
//@Configuration
//@EnableAuthorizationServer
//public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
//
//    /**
//     * 配置自定义数据源，覆盖spring security oauth2自带的
//     *
//     * @return
//     */
//    @Bean
//    @Primary //有多个配置实现时指定要使用的配置
//    @ConfigurationProperties(prefix = "spring.datasource") //指定自定义数据源
//    public DataSource dataSource() {
//        return DataSourceBuilder.create().build();
//    }
//
//    //给jdbc模式的TokenStore配置数据源处理token的存取
//    @Bean
//    public TokenStore jdbcTokenStore() {
//        return new JdbcTokenStore(dataSource());
//    }
//
//    //给jdbc模式的ClientDetailsService 服务配置数据源处理client相关信息的存取，需要数据库提前有值才可取出比对
//    @Bean
//    public ClientDetailsService jdbcClientDetailsService() {
//        return new JdbcClientDetailsService(dataSource());
//    }
//
//    //配置token的处理方式为jdbc模式
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.tokenStore(jdbcTokenStore());
//    }
//
//    //配置client相关信息的处理方式为jdbc模式
//    @Override
//    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.withClientDetails(jdbcClientDetailsService());
//    }
//}


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * 这是redis token方式
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    public PasswordEncoder passwordEncoder;

    @Autowired
    public UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenStore redisTokenStore;

    /**
     * redis token 方式
     */
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)  // 调用此方法才能支持 password 模式
                .userDetailsService(userDetailsService)     // 设置用户验证服务
                .tokenStore(redisTokenStore);                   //指定 token 的存储方式
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("user-client")
                .secret(passwordEncoder.encode("user-secret"))
                .authorizedGrantTypes("refresh_token", "authorization_code", "password")
                .accessTokenValiditySeconds(3600)
                .scopes("all")
                .resourceIds("test_resource")
                .redirectUris("https://www.bilibili.com/");
    }
//    http://localhost:8080/oauth/authorize?client_id=user-client&client_secret=user-secret&response_type=code&redirect_uri=https://www.bilibili.com/

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients();
        security.checkTokenAccess("isAuthenticated()");
        security.tokenKeyAccess("isAuthenticated()");
    }

}