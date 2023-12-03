package io.security.basicsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 테스트 용 사용자 추가
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()  // 인가에 대한 설정
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated() // 모든 요청은 인가를 받은 상태에서 접근 가능
        ;

        http
                .sessionManagement()  // 동시 세션 제어와 간련된 필터 설정
                    .sessionFixation().changeSessionId()  // 기본값, 사용자가 요청할때마다 JSESSIONID 와 같은 값을 항상 변경 (해커 등 공격자의 JSESSIONID 사용을 방지)
//                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)  // 항상 세션을 사용
//                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)  // 스프링 시큐리티가 필요 시 생성 (기본값)
//                    .sessionCreationPolicy(SessionCreationPolicy.NEVER)  // 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
//                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
                .maximumSessions(1)  // 최대 허용 가능 세션 수, -1 : 무제한 로그인 허용
                .maxSessionsPreventsLogin(true)  // 동일한 계정으로 동시 로그인 차단함, 기본값 false
                .expiredUrl("/expired")  // 세션이 만료된 경우 이동 할 페이지
        ;

        http
                .formLogin()  // form 을 통한 인증 필드 설정
//                .loginPage("/loginPage")  // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")  // 로그인 성공 후 이동 페이지
                .failureUrl("/login")  // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")  // 아이디 파라미터명 설정
                .passwordParameter("userpw")  // 패스워드 파라미터명 설정
//                .loginProcessingUrl("/login")  // 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // authentication - 로그인 성공 후 생성되는 인증 객체
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");

                        // 사용자가 인증/인가 예외처리에 따라 로그인 후 이전에 접근하려는 정보가 있다면 찾아서 해당 경로로 이동하도록 처리
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                })  // 로그인 성공 후 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        // exception - 인증 시 발생한 예외 객체
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })  // 로그인 실패 후 핸들러
                .permitAll()  // 인가 정책에 모든 요청은 인가를 받아야하지만 login form 은 누구나 접속 가능하도록 설정
        ;

        http
                .logout()  // 로그아웃 필터 등록
                .logoutUrl("/logout")  // 로그아웃 처리 URL
                .logoutSuccessUrl("/login")  // 로그아웃 성공 후 이동페이지
                .deleteCookies("remember-me")  // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })  // 로그아웃 핸들러 (스프링 시큐리티가 제공하는 핸들러가 있지만 필요하다면 재정의해서 사용 가능)
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })  // 로그아웃 성공 후 핸들러
        ;

        http
                .rememberMe()  // RememberMeAuthenticationFilter 필터 등록
                .rememberMeParameter("rememberMe")  // 파라미터명 변경
                .tokenValiditySeconds(3600)  // Default 14일
//                .alwaysRemember(true)  // RememberMe 기능이 활성화되지 않아도 항상 실행 (일반적으로 false 처리한다. 샘플에서만 true 테스트)
                .userDetailsService(userDetailsService)
        ;

        http
                .exceptionHandling()
//                    .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                        @Override
//                        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                            // login 패스를 아래와 같이 명시적으로 정의하면 스프링 시큐리티의 로그인 페이지가 아닌 controller 에 등록된 login 패스를 구형해야 한다.
//                            response.sendRedirect("/login");
//                        }
//                    })
                    .accessDeniedHandler(new AccessDeniedHandler() {
                        @Override
                        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                            response.sendRedirect("/denied");
                        }
                    })
                ;
    }
}
