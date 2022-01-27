package io.security.coreSpringSecurity.controller.user;


import io.security.coreSpringSecurity.domain.dto.AccountDto;
import io.security.coreSpringSecurity.domain.entity.Account;
import io.security.coreSpringSecurity.domain.entity.Role;
import io.security.coreSpringSecurity.repository.RoleRepository;
import io.security.coreSpringSecurity.security.service.AccountContext;
import io.security.coreSpringSecurity.security.token.AjaxAuthenticationToken;
import io.security.coreSpringSecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Controller
public class UserController {
	
	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RoleRepository roleRepository;

	@GetMapping(value="/users")
	public String createUser() throws Exception {

		return "user/login/register";
	}

	@PostMapping(value="/users")
	public String createUser(AccountDto accountDto) throws Exception {

		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(accountDto.getPassword()));

		userService.createUser(account);

		return "redirect:/";
	}

	@GetMapping(value="/mypage")
	public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) throws Exception {

		userService.order();

		return "user/mypage";
	}
	@GetMapping(value="/order")
	public String order() throws Exception {
		userService.order();
		return "user/mypage";
	}
}
