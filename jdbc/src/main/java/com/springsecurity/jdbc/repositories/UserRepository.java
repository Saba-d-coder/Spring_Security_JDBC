package com.springsecurity.jdbc.repositories;

import com.springsecurity.jdbc.models.User;
import com.springsecurity.jdbc.repositories.utils.UserRowMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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

    public int signUp(User user){
        KeyHolder keyHolder = new GeneratedKeyHolder();

        logger.info("details ot enter: "+ user.getUserName()+ " : " + user.getPassword());
        try{
            String query = "insert into user(username,password) values(?,?)";
            jdbcTemplate.update(
                    new PreparedStatementCreator() {
                        public PreparedStatement createPreparedStatement(Connection connection) throws SQLException {
                            PreparedStatement ps = connection.prepareStatement(query, new String[]{"userID"});
                            ps.setString(1, user.getUserName());
                            ps.setString(2, user.getPassword());
                            return ps;
                        }
                    }, keyHolder);
            logger.info("userResponse= " + Objects.requireNonNull(keyHolder.getKey()).intValue());
            //                System.out.println(userResponse.get(0));
            return Objects.requireNonNull(keyHolder.getKey()).intValue();
        } catch (Exception e) {
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return 0;

    }
}
