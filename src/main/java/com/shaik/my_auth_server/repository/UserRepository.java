package com.shaik.my_auth_server.repository;

import com.shaik.my_auth_server.entity.User;
import com.shaik.my_auth_server.entity.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.text.html.Option;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByProviderIdAndProviderType(String providerId, AuthProviderType providerType);
}
