package com.apps.quantitymeasurement;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.apps.quantitymeasurement.controller.QuantityMeasurementController;
import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.exception.QuantityMeasurementException;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.repository.QuantityMeasurementCacheRepository;
import com.apps.quantitymeasurement.service.IQuantityMeasurementService;
import com.apps.quantitymeasurement.service.QuantityMeasurementServiceImpl;

public class QuantityMeasurementAppTest {
	private static IQuantityMeasurementRepository repository;
	private static IQuantityMeasurementService service;
	private static QuantityMeasurementController controller;
	
	@BeforeAll
	public static void intialize() {
		repository = QuantityMeasurementCacheRepository.getInstance();
		service = new QuantityMeasurementServiceImpl(repository);
        controller = new QuantityMeasurementController(service);
	}
	
	@Test
	public void addLengthFeetAndInches() {
	    QuantityDTO feet = new QuantityDTO(1.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO inches = new QuantityDTO(12.0, QuantityDTO.LengthUnit.INCHES);

	    QuantityDTO result = controller.performAdd(feet, inches);

	    assertEquals(2.0, result.getValue());
	}

	@Test
	public void subtractLengthFeetAndInches() {
	    QuantityDTO feet = new QuantityDTO(5.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO inches = new QuantityDTO(12.0, QuantityDTO.LengthUnit.INCHES);

	    QuantityDTO result = controller.performSubtract(feet, inches);

	    assertEquals(4.0, result.getValue());
	}

	@Test
	public void divideLengthFeet() {
	    QuantityDTO length1 = new QuantityDTO(10.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO length2 = new QuantityDTO(5.0, QuantityDTO.LengthUnit.FEET);

	    double result = controller.performDivide(length1, length2);

	    assertEquals(2.0, result);
	}

	@Test
	public void addWeightKilogramsAndGrams() {
	    QuantityDTO kg = new QuantityDTO(1.0, QuantityDTO.WeightUnit.KILOGRAM);
	    QuantityDTO grams = new QuantityDTO(500.0, QuantityDTO.WeightUnit.GRAM);

	    QuantityDTO result = controller.performAdd(kg, grams);

	    assertEquals(1.5, result.getValue());
	}

	@Test
	public void subtractWeightKilogramsAndGrams() {
	    QuantityDTO kg = new QuantityDTO(2.0, QuantityDTO.WeightUnit.KILOGRAM);
	    QuantityDTO grams = new QuantityDTO(500.0, QuantityDTO.WeightUnit.GRAM);

	    QuantityDTO result = controller.performSubtract(kg, grams);

	    assertEquals(1.5, result.getValue());
	}

	@Test
	public void addVolumeLitersAndMillilitres() {
	    QuantityDTO liter = new QuantityDTO(1.0, QuantityDTO.VolumeUnit.LITRE);
	    QuantityDTO ml = new QuantityDTO(500.0, QuantityDTO.VolumeUnit.MILLILITRE);

	    QuantityDTO result = controller.performAdd(liter, ml);

	    assertEquals(1.5, result.getValue());
	}

	@Test
	public void convertVolumeLitersToMillilitres() {
	    QuantityDTO liter = new QuantityDTO(1.0, QuantityDTO.VolumeUnit.LITRE);
	    QuantityDTO ml = new QuantityDTO(0, QuantityDTO.VolumeUnit.MILLILITRE);

	    QuantityDTO result = controller.performConvert(liter, "MILLILITRE");

	    assertEquals(1000.0, result.getValue());
	}

	@Test
	public void preventLengthWeightAddition() {
	    QuantityDTO length = new QuantityDTO(1.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO weight = new QuantityDTO(1.0, QuantityDTO.WeightUnit.KILOGRAM);

	    assertThrows(QuantityMeasurementException.class,
	            () -> controller.performAdd(length, weight)
	    );
	}

	@Test
	public void preventLengthVolumeComparison() {
	    QuantityDTO length = new QuantityDTO(1.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO volume = new QuantityDTO(1.0, QuantityDTO.VolumeUnit.LITRE);

	    assertThrows(
	            QuantityMeasurementException.class,
	            () -> controller.performCompare(length, volume)
	    );
	}

	@Test
	public void preventDivisionByZero() {
	    QuantityDTO length1 = new QuantityDTO(10.0, QuantityDTO.LengthUnit.FEET);
	    QuantityDTO zeroLength = new QuantityDTO(0.0, QuantityDTO.LengthUnit.FEET);

	    assertThrows(
	            QuantityMeasurementException.class,
	            () -> controller.performDivide(length1, zeroLength)
	    );
	}
}