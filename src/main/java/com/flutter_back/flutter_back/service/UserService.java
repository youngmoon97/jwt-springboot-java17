package com.flutter_back.flutter_back.service;

import com.flutter_back.flutter_back.domain.Users;

import jakarta.servlet.http.HttpServletRequest;

public interface UserService {

    // 회원 등록
    public boolean insert(Users user) throws Exception;

    // 회원 조회
    public Users select(String username) throws Exception;
    
    // 로그인
    public void login(Users user, HttpServletRequest request) throws Exception;

    // 회원 수정
    public boolean update(Users user) throws Exception;

    // 회원 삭제
    public boolean delete(String username) throws Exception;

    
}
