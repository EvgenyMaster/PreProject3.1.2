package application.services;


import application.models.User;

import java.util.List;

public interface UserService {
    List<User> getAllUsers();

    void add(User user);

    void delete(User user);

    void update(User user);

    User getById(long id);

    User getByName(String name);
}

