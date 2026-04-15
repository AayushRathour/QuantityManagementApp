package com.qma_microservices.quantity_service.repository;

import com.qma_microservices.quantity_service.entity.QuantityMeasurementEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface QuantityMeasurementRepository extends JpaRepository<QuantityMeasurementEntity, Long> {
    List<QuantityMeasurementEntity> findByOperation(String operation);

    List<QuantityMeasurementEntity> findByThisMeasurementType(String measurementType);

    List<QuantityMeasurementEntity> findByCreatedAtAfter(LocalDateTime date);

    // Custom JPQL query for complex operations
    @Query("SELECT e FROM QuantityMeasurementEntity e WHERE e.operation = :operation " + "AND e.isError = false")
    List<QuantityMeasurementEntity> findSuccessfulOperations(
            @Param("operation") String operation
    );

    long countByOperationAndIsErrorFalse(String operation);

    List<QuantityMeasurementEntity> findByIsErrorTrue();
}