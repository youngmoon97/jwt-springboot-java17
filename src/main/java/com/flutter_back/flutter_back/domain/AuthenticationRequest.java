package com.flutter_back.flutter_back.domain;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthenticationRequest {

	private String username;            // 아이디
	private String password;            // 비밀번호

}