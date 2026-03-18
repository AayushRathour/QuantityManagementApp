package com.apps.quantitymeasurement.integrationTests;

import com.apps.quantitymeasurement.controller.QuantityMeasurementController;
import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.repository.QuantityMeasurementDatabaseRepository;
import com.apps.quantitymeasurement.service.IQuantityMeasurementService;
import com.apps.quantitymeasurement.service.QuantityMeasurementServiceImpl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementIntegrationTest {
    private QuantityMeasurementController controller;
    private IQuantityMeasurementRepository repository;

    @BeforeEach
    void setup() {
        repository = QuantityMeasurementDatabaseRepository.getInstance();

        IQuantityMeasurementService service =
                new QuantityMeasurementServiceImpl(repository);

        controller = new QuantityMeasurementController(service);
    }

    @Test
    void testEndToEndLengthComparison() {
        QuantityDTO q1 = new QuantityDTO(1, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        boolean result = controller.performCompare(q1, q2);

        assertTrue(result);
    }

    @Test
    void testEndToEndTemperatureComparison() {
        QuantityDTO celsius = new QuantityDTO(0, QuantityDTO.TemperatureUnit.CELSIUS);
        QuantityDTO fahrenheit = new QuantityDTO(32, QuantityDTO.TemperatureUnit.FAHRENHEIT);

        boolean result = controller.performCompare(celsius, fahrenheit);

        assertTrue(result);
    }

    @Test
    void testEndToEndAddition() {
        QuantityDTO q1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        QuantityDTO result = controller.performAdd(q1, q2);

        assertEquals(11, result.getValue());
    }

    @Test
    void testEndToEndConversion() {
        QuantityDTO weight = new QuantityDTO(1, QuantityDTO.WeightUnit.KILOGRAM);

        QuantityDTO result = controller.performConvert(weight, "GRAM");

        assertEquals(1000, result.getValue());
    }

    @Test
    void testRepositoryPersistence() {
        QuantityDTO q1 = new QuantityDTO(5, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(5, QuantityDTO.LengthUnit.FEET);

        controller.performAdd(q1, q2);

        assertTrue(repository.getAllMeasurements().size() > 0);
    }
}