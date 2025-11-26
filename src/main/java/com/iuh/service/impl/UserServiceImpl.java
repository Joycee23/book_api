package com.iuh.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.iuh.constant.AppConstant;
import com.iuh.constant.PredefinedRole;
import com.iuh.dto.request.UserCreationRequest;
import com.iuh.dto.request.UserUpdateAvatarRequest;
import com.iuh.dto.request.UserUpdatePasswordRequest;
import com.iuh.dto.request.UserUpdateRequest;
import com.iuh.dto.response.PageResponse;
import com.iuh.dto.response.UserResponse;
import com.iuh.entity.Role;
import com.iuh.entity.User;
import com.iuh.enums.UserStatus;
import com.iuh.exception.AppException;
import com.iuh.exception.ErrorCode;
import com.iuh.mapper.UserMapper;
import com.iuh.repository.RoleRepository;
import com.iuh.repository.UserRepository;
import com.iuh.repository.specification.UserSpecificationsBuilder;

import com.iuh.service.UserService;
import com.iuh.util.PageUtil;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserServiceImpl implements UserService {

    UserRepository userRepository;
    RoleRepository roleRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder;

    /**
     * Save user to database
     *
     * @param request UserCreationRequest
     * @return UserResponse
     */
    @Override
    @Transactional
    public UserResponse save(UserCreationRequest request) {
        User user = userMapper.toEntity(request);

        String avatarName = user.getName().replace(" ", "+");
        user.setAvatar("https://ui-avatars.com/api/?background=random&rounded=true&bold=true&name=" + avatarName);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setAddresses(new HashSet<>());

        var roles = new HashSet<Role>();
        roleRepository.findById(PredefinedRole.USER_ROLE).ifPresent(roles::add);
        user.setRoles(roles);

        try {
            user = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new AppException(ErrorCode.USER_EXISTS);
        }

        return userMapper.toResponse(user);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public UserResponse findById(String id) {
        User user = getUserById(id);
        return userMapper.toResponse(user);
    }

    /**
     * Get user info from database
     *
     * @return UserResponse
     */
    @Override
    public UserResponse getMyInfo() {
        String username = getCurrentUsername();
        log.debug("Getting user info for username: {}", username);

        if (username == null || username.equals("anonymousUser")) {
            log.error("No authenticated user found or user is anonymous");
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        return userMapper.toResponse(user);
    }

    /**
     * Update user by id
     *
     * @param id      User id
     * @param request UserUpdateRequest
     * @return UserResponse
     */
    @Override
    @Transactional
    @PostAuthorize("returnObject.username == authentication.name")
    public UserResponse update(String id, UserUpdateRequest request) {
        User user = getUserById(id);
        userMapper.updateUser(user, request);
        User updatedUser = userRepository.save(user);

        return userMapper.toResponse(updatedUser);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(String id) {
        userRepository.deleteById(id);
    }

    /**
     * Find all users with sorting and pagination
     *
     * @param pageNo   int
     * @param pageSize int
     * @param sortBy   String
     * @param search   String
     * @return PageResponse
     */
    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<Object> findAll(int pageNo, int pageSize, String sortBy, String search) {
        Pageable pageable = PageUtil.getPageable(pageNo, pageSize, sortBy);
        Page<User> users = userRepository.findAllAndSearch(search, search, search, search, pageable);
        List<UserResponse> items = users.map(userMapper::toResponse).getContent();

        return PageUtil.getPageResponse(pageable, users, items);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<Object> findAllWithSpecifications(int pageNo, int pageSize, String sortBy, String[] users) {
        if (users == null || users.length == 0) {
            return findAll(pageNo, pageSize, sortBy, "");
        }

        UserSpecificationsBuilder builder = new UserSpecificationsBuilder();
        Pattern pattern = Pattern.compile(AppConstant.SEARCH_SPEC_OPERATOR);

        for (String s : users) {
            Matcher matcher = pattern.matcher(s);
            if (matcher.find())
                builder.with(matcher.group(1), matcher.group(2), matcher.group(3), matcher.group(4), matcher.group(5));
        }

        Pageable pageable = PageUtil.getPageable(pageNo, pageSize, sortBy);
        Page<User> usersPage = userRepository.findAll(builder.build(), pageable);
        List<UserResponse> items = usersPage.map(userMapper::toResponse).getContent();

        return PageUtil.getPageResponse(pageable, usersPage, items);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void updateStatus(String id, UserStatus status) {
        User user = getUserById(id);
        user.setStatus(status);
        userRepository.save(user);
    }

    @Override
    public void updatePassword(String id, UserUpdatePasswordRequest request) {
        User user = getUserById(id);

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.INCORRECT_OLD_PASSWORD);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    @Override
    public void updateAvatar(String id, UserUpdateAvatarRequest request) {
        User user = getUserById(id);
        user.setAvatar(request.getAvatar());
        userRepository.save(user);
    }

    /**
     * Get user by ID or throw exception if not found
     */
    private User getUserById(String id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));
    }

    /**
     * Get current authenticated username
     */
    private String getCurrentUsername() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("Authentication object: {}", authentication);
        log.debug("Authentication name: {}", authentication.getName());
        log.debug("Authentication principal: {}", authentication.getPrincipal());
        return authentication.getName();
    }

}