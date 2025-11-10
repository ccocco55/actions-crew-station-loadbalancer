package com.example.crewstation.repository.member;

import com.example.crewstation.domain.address.AddressVO;
import com.example.crewstation.mapper.member.AddressMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
@Slf4j
public class AddressDAO {
    private final AddressMapper addressMapper;
    //    회원가입 시 주소
    public void save(AddressVO addressVO){
        addressMapper.insert(addressVO);
    }

    // 주소 수정
    public int update(AddressVO addressVO) {
        return addressMapper.updateAddress(addressVO);
    }

}
