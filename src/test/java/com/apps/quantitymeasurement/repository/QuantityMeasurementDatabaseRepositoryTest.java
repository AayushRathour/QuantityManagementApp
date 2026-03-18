package com.apps.quantitymeasurement.repository;

import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.entity.QuantityModel;
import com.apps.quantitymeasurement.unit.IMeasurable;
import com.apps.quantitymeasurement.unit.LengthUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementDatabaseRepositoryTest {

    private QuantityMeasurementDatabaseRepository repository;
    @BeforeEach
    void setup() {
        repository = QuantityMeasurementDatabaseRepository.getInstance();
        repository.deleteAll(); // clean DB before each test
    }

    @Test
    void testSingletonInstance() {
        QuantityMeasurementDatabaseRepository repo2 =
                QuantityMeasurementDatabaseRepository.getInstance();

        assertSame(repository, repo2);
    }

    @Test
    void testSaveAndGetAllMeasurements() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "ADD");

        repository.save(entity);

        List<QuantityMeasurementEntity> list =
                repository.getAllMeasurements();

        assertEquals(1, list.size());
        assertEquals("ADD", list.get(0).operation);
    }

    @Test
    void testGetMeasurementsByOperation() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(5, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(5, LengthUnit.FEET);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "COMPARE");

        repository.save(entity);

        List<QuantityMeasurementEntity> result =
                repository.getMeasurementsByOperation("COMPARE");

        assertEquals(1, result.size());
        assertEquals("COMPARE", result.get(0).operation);
    }

    @Test
    void testGetMeasurementsByType() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(5, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(10, LengthUnit.FEET);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "ADD");

        repository.save(entity);

        List<QuantityMeasurementEntity> result =
                repository.getMeasurementsByType("LengthUnit");

        assertEquals(1, result.size());
    }

    @Test
    void testGetTotalCount() {

        QuantityModel<IMeasurable> q1 = new QuantityModel<>(1, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        repository.save(new QuantityMeasurementEntity(q1, q2, "COMPARE"));
        repository.save(new QuantityMeasurementEntity(q1, q2, "ADD"));

        int count = repository.getTotalCount();

        assertEquals(2, count);
    }

    @Test
    void testDeleteAll() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        repository.save(new QuantityMeasurementEntity(q1, q2, "ADD"));

        repository.deleteAll();

        int count = repository.getTotalCount();

        assertEquals(0, count);
    }

    @Test
    void testGetPoolStatistics() {
        String stats = repository.getPoolStatistics();

        assertNotNull(stats);
    }
}