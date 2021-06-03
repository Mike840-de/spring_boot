package com.example.demo.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class MySimpleUrlAuthenticationSucessHandler implements AuthenticationSuccessHandler {

  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      Authentication authentication)
      throws IOException, ServletException {
      handle(httpServletRequest, httpServletResponse, authentication);
  }

  protected void handle(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {

    String targetUrl = determineTargetUrl(authentication);

    if (response.isCommitted()) {
      // logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
      return;
    }

    redirectStrategy.sendRedirect(request, response, targetUrl);
  }

  protected String determineTargetUrl(final Authentication authentication){
      Map<String, String> roleTargetUrlMap = new HashMap<>();
      roleTargetUrlMap.put("ROLE_USER", "/user");
      roleTargetUrlMap.put("ROLE_ADMIN", "/admin");

      final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
      for(final GrantedAuthority grantedAuthority: authorities){
          String authorityName = grantedAuthority.getAuthority();
          if(roleTargetUrlMap.containsKey(authorityName)){
              return roleTargetUrlMap.get(authorityName);
          }
      }
      throw new IllegalStateException();
  }
}
