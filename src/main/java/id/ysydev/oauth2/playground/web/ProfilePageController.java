package id.ysydev.oauth2.playground.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfilePageController {
    @GetMapping("/profile")
    public String profile() {
        return "redirect:/profile.html";
    }
}

