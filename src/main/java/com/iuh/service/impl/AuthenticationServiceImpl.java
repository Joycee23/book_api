package com.iuh.service.impl;

import com.iuh.dto.request.AuthenticationRequest;
import com.iuh.dto.request.IntrospectRequest;
import com.iuh.dto.request.LogoutRequest;
import com.iuh.dto.request.RefreshRequest;
import com.iuh.dto.response.AuthenticationResponse;
import com.iuh.dto.response.IntrospectResponse;
import com.iuh.entity.InvalidatedToken;
import com.iuh.entity.User;
import com.iuh.exception.AppException;
import com.iuh.exception.ErrorCode;
import com.iuh.repository.InvalidatedTokenRepository;
import com.iuh.repository.UserRepository;
import com.iuh.service.AuthenticationService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;

@Slf4j
@Service
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class AuthenticationServiceImpl implements AuthenticationService {
    final UserRepository userRepository;
    final InvalidatedTokenRepository invalidatedTokenRepository;
    final PasswordEncoder passwordEncoder;

    @NonFinal
    @Value("${jwt.signerKey}")
    protected String signerKey;

    @NonFinal
    @Value("${jwt.valid-duration}")
    protected long validDuration;

    @NonFinal
    @Value("${jwt.refreshable-duration}")
    protected long refreshableDuration;

    // Constructor - XÓA @Lazy vì đã tách PasswordEncoder ra config riêng
    public AuthenticationServiceImpl(
            UserRepository userRepository,
            InvalidatedTokenRepository invalidatedTokenRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.invalidatedTokenRepository = invalidatedTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        boolean isValid = true;

        try {
            verifyToken(request.getToken(), false);
        } catch (AppException e) {
            isValid = false;
        }

        return IntrospectResponse.builder().valid(isValid).build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info("=== AUTHENTICATION START ===");
        log.info("🔐 Attempting to authenticate user: {}", request.getUsername());
        log.info("📝 Password from request: {}", request.getPassword());

        var user = userRepository
                .findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    log.error("❌ USER NOT FOUND: {}", request.getUsername());
                    return new AppException(ErrorCode.USER_NOT_FOUND);
                });

        log.info("✅ User found in database");
        log.info("👤 Username from DB: {}", user.getUsername());
        log.info("🔒 Encoded password from DB: {}", user.getPassword());
        log.info("🔑 PasswordEncoder instance: {}", passwordEncoder.getClass().getName());

        // Test password matching
        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());

        log.info("🎯 Password match result: {}", authenticated);

        if (!authenticated) {
            log.error("❌ AUTHENTICATION FAILED - Password does not match!");
            log.error("Raw password: {}", request.getPassword());
            log.error("Expected encoded: {}", user.getPassword());
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        log.info("✅ AUTHENTICATION SUCCESSFUL for user: {}", user.getUsername());
        log.info("=== AUTHENTICATION END ===");

        return AuthenticationResponse.builder()
                .authenticated(true)
                .accessToken(generateAccessToken(user))
                .refreshToken(generateRefreshToken(user))
                .build();
    }

    @Override
    public void logout(LogoutRequest request) throws ParseException, JOSEException {
        try {
            SignedJWT signedJWT = verifyToken(request.getToken(), true);

            String jti = signedJWT.getJWTClaimsSet().getJWTID();
            Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jti).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        } catch (AppException e) {
            log.info("Token is already invalidated");
        }
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws ParseException, JOSEException {
        JWSVerifier jwsVerifier = new MACVerifier(signerKey.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expirationTime = (isRefresh)
                ? new Date(signedJWT
                .getJWTClaimsSet()
                .getIssueTime()
                .toInstant()
                .plus(refreshableDuration, ChronoUnit.SECONDS)
                .toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        if (!(signedJWT.verify(jwsVerifier) && expirationTime.after(new Date())))
            throw new AppException(ErrorCode.INVALID_TOKEN);

        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AppException(ErrorCode.INVALID_TOKEN);

        return signedJWT;
    }

    @Override
    public AuthenticationResponse refreshToken(RefreshRequest request) throws ParseException, JOSEException {
        SignedJWT signedJWT = verifyToken(request.getRefreshToken(), true);

        var jti = signedJWT.getJWTClaimsSet().getJWTID();
        var expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken = InvalidatedToken.builder().id(jti).expiryTime(expiryTime).build();
        invalidatedTokenRepository.save(invalidatedToken);

        var user = userRepository
                .findByUsername(signedJWT.getJWTClaimsSet().getSubject())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND));

        String accessToken = generateAccessToken(user);
        String refreshToken = generateRefreshTokenKeepDuration(user, expiryTime);

        return AuthenticationResponse.builder()
                .authenticated(true)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private String generateToken(User user, long duration) {
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("atuandev.vercel.app")
                .issueTime(new Date())
                .expirationTime(new Date(Instant.now().plus(duration, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(jwsHeader, payload);

        try {
            jwsObject.sign(new MACSigner(signerKey.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new AppException(ErrorCode.UNCATEGORIZED);
        }
    }

    private String generateAccessToken(User user) {
        return generateToken(user, validDuration);
    }

    private String generateRefreshToken(User user) {
        return generateToken(user, refreshableDuration);
    }

    private String generateRefreshTokenKeepDuration(User user, Date duration) {
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("atuandev.vercel.app")
                .issueTime(new Date())
                .expirationTime(duration)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(jwsHeader, payload);

        try {
            jwsObject.sign(new MACSigner(signerKey.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new AppException(ErrorCode.UNCATEGORIZED);
        }
    }

    private String buildScope(User user) {
        StringJoiner joiner = new StringJoiner(" ");

        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                joiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().forEach(permission -> joiner.add(permission.getName()));
            });

        return joiner.toString();
    }
}