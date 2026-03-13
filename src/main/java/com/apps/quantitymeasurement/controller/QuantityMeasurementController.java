package com.apps.quantitymeasurement.controller;

import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.exception.QuantityMeasurementException;
import com.apps.quantitymeasurement.service.IQuantityMeasurementService;

public class QuantityMeasurementController {
    private IQuantityMeasurementService service;

    public QuantityMeasurementController(IQuantityMeasurementService service) {
        this.service = service;
    }

    public boolean performCompare(QuantityDTO q1, QuantityDTO q2) {
    	boolean result = service.compare(q1, q2);
        System.out.println("Comparison Result: " + (result ? "Equal" : "Not Equal"));
        return result;
    }

    public QuantityDTO performConvert(QuantityDTO quantity, String targetUnit) {
    	QuantityDTO result = service.convert(quantity, targetUnit);
        System.out.println("Converted Result: " + result.getValue() + " " + result.getUnit().getUnitName());
        return result;
    }

    public QuantityDTO performAdd(QuantityDTO q1, QuantityDTO q2) {
    	QuantityDTO result = service.add(q1, q2);
        System.out.println("Addition Result: " + result.getValue() + " " + result.getUnit().getUnitName());
        return result;
    }

    public QuantityDTO performSubtract(QuantityDTO q1, QuantityDTO q2) {
    	QuantityDTO result = service.subtract(q1, q2);
        System.out.println("Subtraction Result: " + result.getValue() + " " + result.getUnit().getUnitName());
        return result;
    }

    public double performDivide(QuantityDTO q1, QuantityDTO q2) {
    	double result = service.divide(q1, q2);
        System.out.println("Division Result: " + result);
        return result;
    }
}