package com.example.crewstation.config.mybatis.handler;
import com.example.crewstation.common.enumeration.AccompanyStatus;
import com.example.crewstation.common.enumeration.DeliveryMethod;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;
import org.apache.ibatis.type.TypeHandler;

import java.sql.*;

@MappedTypes(AccompanyStatus.class)
@Slf4j
public class AccompanyStatusHandler implements TypeHandler<AccompanyStatus> {
    @Override
    public void setParameter(PreparedStatement ps, int i, AccompanyStatus parameter, JdbcType jdbcType) throws SQLException {
        log.info("AccompanyStatusHandler.setParameter {}", parameter);
        ps.setObject(i, parameter.getValue(), Types.OTHER);
    }

    @Override
    public AccompanyStatus getResult(ResultSet rs, String columnName) throws SQLException {
        return switch (rs.getString(columnName)){
            case "long" -> AccompanyStatus.LONG;
            case "short" -> AccompanyStatus.SHORT;
            default -> null;
        };
    }

    @Override
    public AccompanyStatus getResult(ResultSet rs, int columnIndex) throws SQLException {
        return switch (rs.getString(columnIndex)){
            case "long" -> AccompanyStatus.LONG;
            case "short" -> AccompanyStatus.SHORT;
            default -> null;
        };
    }

    @Override
    public AccompanyStatus getResult(CallableStatement cs, int columnIndex) throws SQLException {
        return switch (cs.getString(columnIndex)){
            case "long" -> AccompanyStatus.LONG;
            case "short" -> AccompanyStatus.SHORT;
            default -> null;
        };
    }
}
