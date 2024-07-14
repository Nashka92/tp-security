package com.m2ibank.controller;

import com.m2ibank.model.Accounts;
import com.m2ibank.repository.AccountsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AccountController {

    @Autowired
    private AccountsRepository accountsRepository;

    @GetMapping("/myAccount")
    public List <Accounts> getAccountDetails(@RequestParam int id) {
       List<Accounts> accounts = accountsRepository.findByCustomerId(id);
        if (accounts != null ) {
            return accounts;
        }else {
            return null;
        }
    }


    @PostMapping("/createAccount")
    public Accounts createAccount(@RequestBody Accounts account) {
        return accountsRepository.save(account);
    }

}
