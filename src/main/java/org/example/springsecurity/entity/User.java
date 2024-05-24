package org.example.springsecurity.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name ="users")
@Data
public class User {
    @Id
    @GeneratedValue
    private Integer id;
    private String username;
    private String password;
}