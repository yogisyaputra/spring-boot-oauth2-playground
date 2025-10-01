package id.ysydev.oauth2.playground.user_provider;

import id.ysydev.oauth2.playground.user.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity @Table(name = "user_provider_accounts",
        uniqueConstraints = @UniqueConstraint(name = "uq_provider_user", columnNames = {"provider","provider_user_id"}))
@Setter @Getter
public class UserProviderAccount {
    @Id
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, length = 32)
    private String provider; // "google" | "github"

    @Column(name = "provider_user_id", nullable = false, length = 128)
    private String providerUserId;

    private String username;
    @Column(name = "profile_url") private String profileUrl;

    @PrePersist
    void prePersist() { if (id == null) id = UUID.randomUUID(); }

}