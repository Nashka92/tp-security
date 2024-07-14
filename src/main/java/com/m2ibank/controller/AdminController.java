package com.m2ibank.controller;


import com.m2ibank.model.*;
import com.m2ibank.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private LoanRepository loansRepository;

    @Autowired
    private AccountsRepository accountsRepository;

    @Autowired
    private CardsRepository cardsRepository;

    @Autowired
    private AccountTransactionsRepository accountTransactionsRepository;


    @GetMapping("/loans")
    public Iterable<Loans> getAllLoans() {
        return loansRepository.findAll();
    }

    @GetMapping("/accounts")
    public Iterable<Accounts> getAllAccounts() {
        return accountsRepository.findAll();
    }

    @GetMapping("/cards")
    public Iterable<Cards> getAllCards() {
        return cardsRepository.findAll();
    }

    @GetMapping("/transactions")
    public Iterable<AccountTransactions> getAllTransactions() {
        return accountTransactionsRepository.findAll();
    }


}

