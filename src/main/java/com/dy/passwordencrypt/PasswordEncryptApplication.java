package com.dy.passwordencrypt;

import com.dy.passwordencrypt.utils.BouncyRSAUtils;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class PasswordEncryptApplication {

    public static void main(String[] args) {
        SpringApplication.run(PasswordEncryptApplication.class, args);
    }

    @Bean
    public static BeanPostProcessor beanPostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
                if (bean instanceof HikariDataSource) {
                    HikariDataSource hikariDataSource = (HikariDataSource) bean;
                    try {
                        String decrypted = BouncyRSAUtils.decrypt(hikariDataSource.getPassword(), BouncyRSAUtils.defaultPublicKey);
                        hikariDataSource.setPassword(decrypted);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                return null;
            }
        };
    }

}
