package com.masker.formlogin;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class VerifyCodeFilter extends GenericFilter {
    private String defaultProcessFilterUrl = "/login.html";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if("POST".equalsIgnoreCase(req.getMethod())
                && defaultProcessFilterUrl.equalsIgnoreCase(req.getServletPath())){
            String requestCaptcha = req.getParameter("code");
            String genericCaptcha = (String) req.getSession().getAttribute("verify_code");

            if(requestCaptcha.isEmpty()){
                throw new AuthenticationServiceException("验证码不能为空！");
            }

            if (!((requestCaptcha.toLowerCase()).equalsIgnoreCase(genericCaptcha.toLowerCase()))){
                throw new AuthenticationServiceException("输入验证码错误！");
            }
        }

        chain.doFilter(request,response);
    }
}
