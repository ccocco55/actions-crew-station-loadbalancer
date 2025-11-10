package com.example.crewstation.config.mybatis.converter;

import com.example.crewstation.common.enumeration.AccompanyStatus;
import com.example.crewstation.common.enumeration.Gender;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class AccompanyConverter implements Converter<String, AccompanyStatus> {
    @Override
    public AccompanyStatus convert(String source) {
        return AccompanyStatus.getAccompanyStatusFromValue(source);
    }

}
