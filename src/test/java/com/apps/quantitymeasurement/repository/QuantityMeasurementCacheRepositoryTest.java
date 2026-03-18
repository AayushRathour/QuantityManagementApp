package com.apps.quantitymeasurement.repository;

import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.entity.QuantityModel;
import com.apps.quantitymeasurement.unit.IMeasurable;
import com.apps.quantitymeasurement.unit.LengthUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementCacheRepositoryTest {

    private QuantityMeasurementCacheRepository repository;

    @BeforeEach
    void setup() {

        // Remove file to start fresh
        File file = new File(QuantityMeasurementCacheRepository.FILE_NAME);
        if (file.exists()) {
            file.delete();
        }

        repository = QuantityMeasurementCacheRepository.getInstance();
    }

    @Test
    void testSingletonInstance() {

        QuantityMeasurementCacheRepository repo2 =
                QuantityMeasurementCacheRepository.getInstance();

        assertSame(repository, repo2);
    }

    @Test
    void testSaveEntity() {

        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "ADD");

        repository.save(entity);

        List<QuantityMeasurementEntity> list = repository.getAllMeasurements();

        assertEquals(1, list.size());
        assertEquals("ADD", list.get(0).operation);
    }

    @Test
    void testGetAllMeasurements() {

        QuantityModel<IMeasurable> q1 = new QuantityModel<>(5, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(5, LengthUnit.FEET);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "COMPARE");

        repository.save(entity);

        List<QuantityMeasurementEntity> measurements =
                repository.getAllMeasurements();

        assertFalse(measurements.isEmpty());
    }

    @Test
    void testFileCreatedAfterSave() {

        QuantityModel<IMeasurable> q1 = new QuantityModel<>(1, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "COMPARE");

        repository.save(entity);

        File file = new File(QuantityMeasurementCacheRepository.FILE_NAME);

        assertTrue(file.exists());
    }
}