package com.springsecurity.jdbc.repositories;

import com.springsecurity.jdbc.models.User;
import com.springsecurity.jdbc.repositories.utils.UserRowMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;

@Repository
public class UserRepository {

    private static final Logger logger = LoggerFactory.getLogger(UserRepository.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public User getUserInfo(String userName) {
        try {
            String query = "select * from user where username=?";
            List<User> userResponse = jdbcTemplate.query(query,new UserRowMapper(),userName);
            logger.info("userResponse= " + userResponse);
            if (userName != null) {
                System.out.println(userResponse.get(0));
                return userResponse.get(0);
            }
        } catch (Exception e) {
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return null;
    }
}
