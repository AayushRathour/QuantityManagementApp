package com.apps.quantitymeasurement.service;

import com.apps.quantitymeasurement.entity.QuantityDTO;

public interface IQuantityMeasurementService {

    boolean compare(QuantityDTO first, QuantityDTO second);

    QuantityDTO convert(QuantityDTO quantity, String targetUnit);

    QuantityDTO add(QuantityDTO first, QuantityDTO second);

    QuantityDTO subtract(QuantityDTO first, QuantityDTO second);

    double divide(QuantityDTO first, QuantityDTO second);
}