package com.flutter_back.flutter_back.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.flutter_back.flutter_back.domain.UserAuth;
import com.flutter_back.flutter_back.domain.Users;

@Mapper
public interface UserMapper {

    // 회원 조회
    public Users select(String id) throws Exception;

    // 회원 가입
    public int join(Users user) throws Exception;

    // 회원 수정
    public int update(Users user) throws Exception;

    // 회원 권한 등록
    public int insertAuth(UserAuth userAuth) throws Exception;

    // 회원 삭제
    public int delete(String username) throws Exception;

}