package com.example.crewstation.config;

import com.example.crewstation.dto.accompany.AccompanyDTO;
import com.example.crewstation.dto.banner.BannerDTO;
import com.example.crewstation.dto.crew.CrewDTO;
import com.example.crewstation.dto.diary.DiaryDTO;
import com.example.crewstation.dto.diary.DiaryDetailDTO;
import com.example.crewstation.dto.gift.GiftDTO;
import com.example.crewstation.dto.member.MemberProfileDTO;
import com.example.crewstation.dto.purchase.PurchaseDTO;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;

import java.time.Duration;
import java.util.Map;

@Configuration
@EnableCaching
public class RedisConfig {
//    Redis 캐시 설정
    @Bean
    public RedisCacheManager redisCacheManager(RedisConnectionFactory factory) {
        RedisCacheConfiguration configuration = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(10)) // 캐시 유지 시간
                .serializeValuesWith(
                        RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer())
                );

        return RedisCacheManager.builder(factory)
                .cacheDefaults(configuration)
                .build();
    }

//    Redis 캐시 직접 조회
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
//        키는 문자열 직렬화
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());

//        값은 JSON 직렬화
        template.setValueSerializer(new Jackson2JsonRedisSerializer<Object>(Object.class));
        template.setHashValueSerializer(new Jackson2JsonRedisSerializer<Object>(Object.class));

        template.afterPropertiesSet();
        return template;
    }

//    Redis 캐시 유지 시간
    public SessionRepositoryCustomizer<RedisIndexedSessionRepository> customizeSessionTimeout() {
        return (repository) -> repository.setDefaultMaxInactiveInterval(Duration.ofMinutes(10));
    }

    @Bean
    public RedisTemplate<String, PurchaseDTO> purchaseRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, PurchaseDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<PurchaseDTO> serializer =
                new Jackson2JsonRedisSerializer<>(PurchaseDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, DiaryDetailDTO> diaryRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, DiaryDetailDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<DiaryDetailDTO> serializer =
                new Jackson2JsonRedisSerializer<>(DiaryDetailDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, CrewDTO> CrewRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, CrewDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<CrewDTO> serializer =
                new Jackson2JsonRedisSerializer<>(CrewDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, AccompanyDTO> AccompanyRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, AccompanyDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<AccompanyDTO> serializer =
                new Jackson2JsonRedisSerializer<>(AccompanyDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, GiftDTO> GiftRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, GiftDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<GiftDTO> serializer =
                new Jackson2JsonRedisSerializer<>(GiftDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, DiaryDTO> DiaryRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, DiaryDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<DiaryDTO> serializer =
                new Jackson2JsonRedisSerializer<>(DiaryDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, BannerDTO> BannerRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, BannerDTO> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        Jackson2JsonRedisSerializer<BannerDTO> serializer =
                new Jackson2JsonRedisSerializer<>(BannerDTO.class);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, Map<String,Long>> countryRedisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Map<String,Long>> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        // Key는 문자열
        template.setKeySerializer(new StringRedisSerializer());
        // Value는 Map<String, Long> 전용 직렬화
        GenericJackson2JsonRedisSerializer serializer = new GenericJackson2JsonRedisSerializer();
        template.setValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

}
