package ch.pfadiaargau.model;

import java.util.List;

public class MidataRole {
    public String group_id;
    public String group_name;
    public String role;
    public String role_class;
    public String role_name;
    public List<String> permissions;

    

    public MidataRole(String group_id, String group_name, String role, String role_class, String role_name,
            List<String> permissions) {
        this.group_id = group_id;
        this.group_name = group_name;
        this.role = role;
        this.role_class = role_class;
        this.role_name = role_name;
        this.permissions = permissions;
    }
    
    public String getGroup_id() {
        return group_id;
    }
    public void setGroup_id(String group_id) {
        this.group_id = group_id;
    }
    public String getGroup_name() {
        return group_name;
    }
    public void setGroup_name(String group_name) {
        this.group_name = group_name;
    }
    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }
    public String getRole_class() {
        return role_class;
    }
    public void setRole_class(String role_class) {
        this.role_class = role_class;
    }
    public String getRole_name() {
        return role_name;
    }
    public void setRole_name(String role_name) {
        this.role_name = role_name;
    }
    public List<String> getPermissions() {
        return permissions;
    }
    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public String toString() {
        return "MidataRole [group_id=" + group_id + ", group_name=" + group_name + ", role=" + role
                + ", role_class=" + role_class + ", role_name=" + role_name + ", permissions=" + permissions + "]";
    }
    
}
