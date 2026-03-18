package com.apps.quantitymeasurement.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.repository.QuantityMeasurementDatabaseRepository;
import com.apps.quantitymeasurement.service.IQuantityMeasurementService;
import com.apps.quantitymeasurement.service.QuantityMeasurementServiceImpl;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementControllerTest {

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
    void testPerformCompareEqual() {
        QuantityDTO feet = new QuantityDTO(1, QuantityDTO.LengthUnit.FEET);
        QuantityDTO inches = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        boolean result = controller.performCompare(feet, inches);

        assertTrue(result);
    }

    @Test
    void testPerformCompareNotEqual() {
        QuantityDTO feet = new QuantityDTO(2, QuantityDTO.LengthUnit.FEET);
        QuantityDTO inches = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        boolean result = controller.performCompare(feet, inches);

        assertFalse(result);
    }

    @Test
    void testPerformConvert() {
        QuantityDTO kg = new QuantityDTO(1, QuantityDTO.WeightUnit.KILOGRAM);

        QuantityDTO result = controller.performConvert(kg, "GRAM");

        assertEquals(1000, result.getValue());
        assertEquals("GRAM", result.getUnit().getUnitName());
    }

    @Test
    void testPerformAdd() {
        QuantityDTO feet = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO inches = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        QuantityDTO result = controller.performAdd(feet, inches);

        assertEquals(11, result.getValue());
    }

    @Test
    void testPerformSubtract() {
        QuantityDTO q1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(6, QuantityDTO.LengthUnit.FEET);

        QuantityDTO result = controller.performSubtract(q1, q2);

        assertEquals(4, result.getValue());
    }

    @Test
    void testPerformDivide() {
        QuantityDTO q1 = new QuantityDTO(20, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(5, QuantityDTO.LengthUnit.FEET);

        double result = controller.performDivide(q1, q2);

        assertEquals(4.0, result);
    }

    @Test
    void testTemperatureCompare() {
        QuantityDTO celsius = new QuantityDTO(0, QuantityDTO.TemperatureUnit.CELSIUS);
        QuantityDTO fahrenheit = new QuantityDTO(32, QuantityDTO.TemperatureUnit.FAHRENHEIT);

        boolean result = controller.performCompare(celsius, fahrenheit);

        assertTrue(result);
    }
}
