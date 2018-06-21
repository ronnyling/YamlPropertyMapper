package com.rhb.dcpbo.security.jwt;

import com.sun.org.apache.xpath.internal.operations.Bool;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
@Slf4j
public class JWTInterceptor extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
        throws IOException, ServletException {

        //Extract URL and return service name
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        try {
            PropertySource<?> applicationYamlPropertySource = loader.load(
                "properties", new ClassPathResource("config/api.yml"), null);// null indicated common properties for all profiles.
            Map source = ((MapPropertySource) applicationYamlPropertySource).getSource();
            Properties properties = new Properties();
            properties.putAll(source);
            Set<Object> keys = properties.keySet();
            Boolean foundURL = false;
            for(Object key: keys) {
                if ("/".concat(String.valueOf(properties.get(key))).equals(((HttpServletRequest) servletRequest).getRequestURI())) {
                    String urlToName = String.valueOf((key)).replace("url","name");
                    log.info(properties.getProperty(urlToName));
                    foundURL = true;
                }
            }
            if (foundURL){}else{
                log.info("Api not exist in api.yml file");
            }
        } catch (IOException e) {
            log.error("api.yml file cannot be found.");
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
