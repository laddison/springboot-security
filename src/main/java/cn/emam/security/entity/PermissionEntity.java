package cn.emam.security.entity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "permission")
@Data
public class PermissionEntity implements Serializable {
    private static final long serialVersionUID = 6715438896629237028L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "url")
    private String url;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "pid")
    private Long pid;
}
