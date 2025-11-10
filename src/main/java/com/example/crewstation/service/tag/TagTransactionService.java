package com.example.crewstation.service.tag;

import com.example.crewstation.dto.country.CountryDTO;
import com.example.crewstation.dto.purchase.PurchaseDTO;
import com.example.crewstation.repository.country.CountryDAO;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TagTransactionService {
    private final RedisTemplate<String, Map<String,Long>> countryRedisTemplate;
    private final CountryDAO countryDAO;

    public Map<String, Long>  getCountries() {
        List<CountryDTO> countryDTOList = countryDAO.findAll();
        Map<String, Long> map = countryDTOList.stream().collect(Collectors.toMap(CountryDTO::getCountryName,CountryDTO::getId));
        countryRedisTemplate.opsForValue().set("country::countries", map, Duration.ofMinutes(10));
        return map;
    }
}
