package com.apps.quantitymeasurement.service;

import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.repository.QuantityMeasurementDatabaseRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementServiceImplTest {
    private IQuantityMeasurementService service;

    @BeforeEach
    void setup() {
        IQuantityMeasurementRepository repository = QuantityMeasurementDatabaseRepository.getInstance();

        repository.getAllMeasurements().clear();

        service = new QuantityMeasurementServiceImpl(repository);
    }

    @Test
    void testCompareEqualLengths() {
        QuantityDTO q1 = new QuantityDTO(1, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        boolean result = service.compare(q1, q2);

        assertTrue(result);
    }

    @Test
    void testCompareNotEqualLengths() {
        QuantityDTO q1 = new QuantityDTO(2, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        boolean result = service.compare(q1, q2);

        assertFalse(result);
    }

    @Test
    void testConvertWeight() {

        QuantityDTO weight = new QuantityDTO(1, QuantityDTO.WeightUnit.KILOGRAM);

        QuantityDTO result = service.convert(weight, "GRAM");

        assertEquals(1000, result.getValue());
        assertEquals("GRAM", result.getUnit().getUnitName());
    }

    @Test
    void testAddLengthUnits() {
        QuantityDTO q1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        QuantityDTO result = service.add(q1, q2);

        assertEquals(11, result.getValue());
        assertEquals("FEET", result.getUnit().getUnitName());
    }

    @Test
    void testSubtractLengthUnits() {
        QuantityDTO q1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(12, QuantityDTO.LengthUnit.INCHES);

        QuantityDTO result = service.subtract(q1, q2);

        assertEquals(9, result.getValue());
    }

    @Test
    void testDivideLengthUnits() {
        QuantityDTO q1 = new QuantityDTO(20, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(5, QuantityDTO.LengthUnit.FEET);

        double result = service.divide(q1, q2);

        assertEquals(4, result);
    }

    @Test
    void testDivideByZero() {
        QuantityDTO q1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO q2 = new QuantityDTO(0, QuantityDTO.LengthUnit.FEET);

        assertThrows(RuntimeException.class, () -> service.divide(q1, q2));
    }

    @Test
    void testAddDifferentMeasurementTypesShouldFail() {
        QuantityDTO length = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO weight = new QuantityDTO(1, QuantityDTO.WeightUnit.KILOGRAM);

        assertThrows(RuntimeException.class, () -> service.add(length, weight));
    }
}