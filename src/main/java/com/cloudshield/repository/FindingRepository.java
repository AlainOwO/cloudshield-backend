package com.cloudshield.repository;

import com.cloudshield.model.SecretFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FindingRepository extends JpaRepository<SecretFinding, Long> {
}