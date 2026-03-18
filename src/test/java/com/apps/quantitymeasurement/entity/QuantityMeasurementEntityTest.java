package com.apps.quantitymeasurement.entity;

import com.apps.quantitymeasurement.unit.IMeasurable;
import com.apps.quantitymeasurement.unit.LengthUnit;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementEntityTest {

    @Test
    void testBasicConstructor() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(120, LengthUnit.INCHES);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "COMPARE");

        assertEquals(10, entity.thisValue);
        assertEquals("FEET", entity.thisUnit);
        assertEquals("LengthUnit", entity.thisMeasurementType);

        assertEquals(120, entity.thatValue);
        assertEquals("INCHES", entity.thatUnit);
        assertEquals("LengthUnit", entity.thatMeasurementType);

        assertEquals("COMPARE", entity.operation);
    }

    @Test
    void testConstructorWithResultString() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(1, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "COMPARE", "Equal");

        assertEquals("COMPARE", entity.operation);
        assertEquals("Equal", entity.resultString);
    }

    @Test
    void testConstructorWithResultModel() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(12, LengthUnit.INCHES);
        QuantityModel<IMeasurable> result = new QuantityModel<>(11, LengthUnit.FEET);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "ADD", result);

        assertEquals("ADD", entity.operation);
        assertEquals(11, entity.resultValue);
        assertEquals("FEET", entity.resultUnit);
        assertEquals("LengthUnit", entity.resultMeasurementType);
    }

    @Test
    void testConstructorWithError() {
        QuantityModel<IMeasurable> q1 = new QuantityModel<>(10, LengthUnit.FEET);
        QuantityModel<IMeasurable> q2 = new QuantityModel<>(0, LengthUnit.FEET);

        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(q1, q2, "DIVIDE", "Division by zero", true);

        assertEquals("DIVIDE", entity.operation);
        assertTrue(entity.isError);
        assertEquals("Division by zero", entity.errorMessage);
    }

    @Test
    void testConstructorWithNullOperands() {
        QuantityMeasurementEntity entity =
                new QuantityMeasurementEntity(null, null, "TEST");

        assertEquals("TEST", entity.operation);

        assertEquals(0, entity.thisValue);
        assertNull(entity.thisUnit);

        assertEquals(0, entity.thatValue);
        assertNull(entity.thatUnit);
    }
}