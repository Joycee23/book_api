// src/com/iuh/service/impl/UserServiceImpl.java (Mã ĐẦY ĐỦ ĐÃ SỬA LỖI)

package com.iuh.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iuh.constant.AppConstant;
import com.iuh.constant.PredefinedRole;
import com.iuh.constant.RedisKey;
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
import com.iuh.service.RedisService;
import com.iuh.service.UserService;
import com.iuh.util.PageUtil;
import jakarta.transaction.Transactional;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
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
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserServiceImpl implements UserService {
    private static final int DEFAULT_CACHE_HOURS = 1;
    private static final int EXTENDED_CACHE_HOURS = 2;

    UserRepository userRepository;
    RoleRepository roleRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder;
    RedisService<String, String, String> redisService;
    ObjectMapper redisObjectMapper;

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
        cacheUser(user, DEFAULT_CACHE_HOURS);
        return userMapper.toResponse(user);
    }

    /**
     * Get user info from cache or database
     *
     * @return UserResponse
     */
    @Override
    public UserResponse getMyInfo() {
        String username = getCurrentUsername();
        return getUserResponseFromCacheOrDatabase(username);
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

        cacheUser(updatedUser, EXTENDED_CACHE_HOURS);
        return userMapper.toResponse(updatedUser);
    }

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(String id) {
        User user = getUserById(id);
        userRepository.deleteById(id);
        removeCachedUser(user.getUsername());
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
        Page<User> users;

        // >>> PHẦN ĐÃ SỬA LỖI: Kiểm tra nếu không có chuỗi tìm kiếm (search là rỗng) <<<
        if (StringUtils.isBlank(search)) {
            // Nếu không có tìm kiếm, gọi phương thức findAll cơ bản
            users = userRepository.findAll(pageable);
            log.warn("Search parameter is blank. Using basic findAll(Pageable). Users found: {}", users.getTotalElements());
        } else {
            // Nếu có chuỗi tìm kiếm, sử dụng logic tìm kiếm tùy chỉnh
            users = userRepository.findAllAndSearch(search, search, search, search, pageable);
            log.warn("Using custom findAllAndSearch logic. Users found: {}", users.getTotalElements());
        }
        // >>> KẾT THÚC PHẦN SỬA LỖI <<<

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
        cacheUser(user, DEFAULT_CACHE_HOURS);
    }

    @Override
    public void updatePassword(String id, UserUpdatePasswordRequest request) {
        User user = getUserById(id);

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.INCORRECT_OLD_PASSWORD);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        cacheUser(user, DEFAULT_CACHE_HOURS);
    }

    @Override
    public void updateAvatar(String id, UserUpdateAvatarRequest request) {
        User user = getUserById(id);
        user.setAvatar(request.getAvatar());
        userRepository.save(user);
        cacheUser(user, DEFAULT_CACHE_HOURS);
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
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    /**
     * Get user from cache or database based on username
     */
    private UserResponse getUserResponseFromCacheOrDatabase(String username) {
        // Try to get user from cache
        User cachedUser = getCachedUser(username);
        if (cachedUser != null) {
            log.debug("Cache hit for user: {}", username);
            return userMapper.toResponse(cachedUser);
        }

        // If not in cache, get from database and cache it
        log.debug("Cache miss for user: {}, fetching from database", username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        cacheUser(user, DEFAULT_CACHE_HOURS);
        return userMapper.toResponse(user);
    }

    /**
     * Get user from cache
     */
    private User getCachedUser(String username) {
        String userJson = redisService.hashGet(RedisKey.USER_INFO, username);
        if (StringUtils.isEmpty(userJson)) {
            return null;
        }

        try {
            return redisObjectMapper.readValue(userJson, User.class);
        } catch (JsonProcessingException e) {
            log.error("Error deserializing cached user: {}", username, e);
            removeCachedUser(username); // Remove invalid cache entry
            return null;
        }
    }

    /**
     * Cache user with specified expiration
     */
    private void cacheUser(User user, int expireHours) {
        try {
            String userJson = redisObjectMapper.writeValueAsString(user);
            redisService.hashSet(RedisKey.USER_INFO, user.getUsername(), userJson);
            redisService.setExpireHours(RedisKey.USER_INFO, expireHours);
            log.debug("User cached successfully: {}", user.getUsername());
        } catch (JsonProcessingException e) {
            log.error("Error serializing user for caching: {}", user.getUsername(), e);
            // Continue without caching - fail gracefully
        }
    }

    /**
     * Remove user from cache
     */
    private void removeCachedUser(String username) {
        redisService.delete(RedisKey.USER_INFO, username);
        log.debug("Removed user from cache: {}", username);
    }
}