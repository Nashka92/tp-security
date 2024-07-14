package com.m2ibank.controller;

import com.m2ibank.model.Cards;
import com.m2ibank.repository.CardsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class CardsController {

    @Autowired
    private CardsRepository cardsRepository;

    @GetMapping("/myCards")
    public List<Cards> getCardDetails(@RequestParam int id) {
        List<Cards> cards = cardsRepository.findByCustomerId(id);
        if (cards != null ) {
            return cards;
        }else {
            return null;
        }
    }

    @PostMapping("/createCard")
    public Cards createCard(@RequestBody Cards card) {

        return cardsRepository.save(card);
    }



}
