package id.ysydev.oauth2.playground.security.gmail;

import lombok.Getter;
import lombok.Setter;

@Setter @Getter
public class GithubEmail {
    private String email;
    private Boolean primary;
    private Boolean verified;
    private String visibility; // public | private | null

}
