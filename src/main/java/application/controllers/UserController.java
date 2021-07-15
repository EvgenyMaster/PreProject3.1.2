package application.controllers;


import application.models.Role;
import application.models.User;
import application.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashSet;
import java.util.Set;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String showSignUpForm() {
        return "login";
    }

    @GetMapping("/admin")
    public String showAdminPage(Model model) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("user", user);
        return "admin";
    }

    @GetMapping("/user")
    public ModelAndView showUser() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("user");
        modelAndView.addObject("user", user);
        return modelAndView;
    }

    @GetMapping("/adduser")

    public String adduser(Model model) {
        User usera = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("usera", usera);
        model.addAttribute("user", new User());
        return "/adduser";
    }

    @PostMapping("/adduser")

    public String saveUser(
            @RequestParam("name") String name,
            @RequestParam("lastname") String lastname,
            @RequestParam("age") int age,
            @RequestParam("email") String email,
            @RequestParam("password") String password,
            @RequestParam(required = false, name = "ADMIN") String ADMIN,
            @RequestParam(required = false, name = "USER") String USER) {


        Set<Role> roles = new HashSet<>();
        if (ADMIN != null) {
            roles.add(new Role(1L, ADMIN));
        }
        if (USER != null) {
            roles.add(new Role(2L, USER));
        }
        if (ADMIN == null && USER == null) {
            roles.add(new Role(2L, USER));
        }

        User user = new User(name, lastname, age, email, password, roles);
        userService.add(user);

        return "redirect:/admin";
    }

    @GetMapping("/edit/{id}")

    public User showUpdateForm(@PathVariable("id") long id) {
        User user = userService.getById(id);
        return user;
    }

    @PostMapping("/edit")
    public String updateUser(@ModelAttribute("user") User user,
                             @RequestParam(required = false, name = "ADMIN") String ADMIN,
                             @RequestParam(required = false, name = "USER") String USER) {

        Set<Role> roles = new HashSet<>();
        if (ADMIN != null) {
            roles.add(new Role(2L, ADMIN));
        }
        if (USER != null) {
            roles.add(new Role(1L, USER));
        }
        if (ADMIN == null && USER == null) {
            roles.add(new Role(1L, USER));
        }
        user.setRoles(roles);
        userService.update(user);
        return "redirect:/admin";
    }

    @DeleteMapping("{id}")
    public String deleteUser(@PathVariable("id") long id, Model model) {
        userService.delete(userService.getById(id));
        model.addAttribute("users", userService.getAllUsers());
        return "redirect:/admin";
    }
}