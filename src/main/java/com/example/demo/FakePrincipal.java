package com.example.demo;

import com.google.common.collect.Sets;

import java.security.Principal;
import java.util.Set;

public class FakePrincipal implements Principal {

    @Override
    public String getName() {
        return "lem_user";
    }

    public Set<String> getDetails(){
        return Sets.newHashSet("Somerandomdetail", "user", "adminstering");
    }
}
