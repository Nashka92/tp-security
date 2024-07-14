package com.m2ibank.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.m2ibank.model.Accounts;

import java.util.List;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {
	
	List<Accounts> findByCustomerId(int customerId);

}
