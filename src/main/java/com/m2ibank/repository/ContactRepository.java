package com.m2ibank.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.m2ibank.model.Contact;

@Repository
public interface ContactRepository extends CrudRepository<Contact, Long> {
	
	
}
