package com.apps.quantitymeasurement.service;

import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.entity.QuantityModel;
import com.apps.quantitymeasurement.exception.QuantityMeasurementException;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.unit.IMeasurable;

public class QuantityMeasurementServiceImpl implements IQuantityMeasurementService {
    private IQuantityMeasurementRepository repository;

    public QuantityMeasurementServiceImpl(IQuantityMeasurementRepository repository) {
        this.repository = repository;
    }

    private QuantityModel<IMeasurable> convertToModel(QuantityDTO dto) {
        try {
            IMeasurable unit = IMeasurable.getUnitInstance(dto.getUnit().getUnitName(),
                            Class.forName("com.apps.quantitymeasurement.unit." + dto.getUnit().getMeasurementType()));
            return new QuantityModel<>(dto.getValue(), unit);
        } 
        catch (Exception e) {
            throw new QuantityMeasurementException("Invalid unit conversion", e);
        }
    }

    private QuantityDTO convertToDTO(QuantityModel<IMeasurable> model) {
        String unitName = model.getUnit().getUnitName();
        String measurementType = model.getUnit().getMeasurementType();

        QuantityDTO.IMeasurableUnit unit;

        if (measurementType.equals("LengthUnit")) {
            unit = QuantityDTO.LengthUnit.valueOf(unitName);
        }
        else if (measurementType.equals("WeightUnit")) {
            unit = QuantityDTO.WeightUnit.valueOf(unitName);
        }
        else if (measurementType.equals("VolumeUnit")) {
            unit = QuantityDTO.VolumeUnit.valueOf(unitName);
        }
        else if (measurementType.equals("TemperatureUnit")) {
            unit = QuantityDTO.TemperatureUnit.valueOf(unitName);
        }
        else {
            throw new QuantityMeasurementException("Invalid measurement type");
        }

        return new QuantityDTO(model.getValue(), unit);
    }

    @Override
    public boolean compare(QuantityDTO first, QuantityDTO second) {
        QuantityModel<IMeasurable> q1 = convertToModel(first);
        QuantityModel<IMeasurable> q2 = convertToModel(second);

        if (!q1.getUnit().getMeasurementType().equals(q2.getUnit().getMeasurementType())) {
            throw new QuantityMeasurementException("Cannot compare quantities of different measurement types");
        }

        double base1 = q1.getUnit().convertToBaseUnit(q1.getValue());
        double base2 = q2.getUnit().convertToBaseUnit(q2.getValue());
        boolean result = Double.compare(base1, base2) == 0;

        repository.save(new QuantityMeasurementEntity(q1, q2, "COMPARE", result ? "Equal" : "Not Equal"));

        return result;
    }

    @Override
    public QuantityDTO convert(QuantityDTO quantity, String targetUnit) {
        QuantityModel<IMeasurable> model = convertToModel(quantity);

        IMeasurable target = IMeasurable.getUnitInstance(targetUnit, model.getUnit().getClass());

        double base = model.getUnit().convertToBaseUnit(model.getValue());

        double converted = target.convertFromBaseUnit(base);

        QuantityModel<IMeasurable> result = new QuantityModel<>(converted, target);

        repository.save(new QuantityMeasurementEntity(model, null, "CONVERT", result));

        return convertToDTO(result);
    }

    @Override
    public QuantityDTO add(QuantityDTO first, QuantityDTO second) {
        QuantityModel<IMeasurable> q1 = convertToModel(first);
        QuantityModel<IMeasurable> q2 = convertToModel(second);

        validateType(q1, q2);

        q1.getUnit().validateOperationSupport("ADD");

        double base = q1.getUnit().convertToBaseUnit(q1.getValue()) + q2.getUnit().convertToBaseUnit(q2.getValue());

        double resultValue = q1.getUnit().convertFromBaseUnit(base);

        QuantityModel<IMeasurable> result = new QuantityModel<>(resultValue, q1.getUnit());

        repository.save(new QuantityMeasurementEntity(q1, q2, "ADD", result));

        return convertToDTO(result);
    }

    @Override
    public QuantityDTO subtract(QuantityDTO first, QuantityDTO second) {
        QuantityModel<IMeasurable> q1 = convertToModel(first);
        QuantityModel<IMeasurable> q2 = convertToModel(second);

        validateType(q1	, q2);

        q1.getUnit().validateOperationSupport("SUBTRACT");

        double base = q1.getUnit().convertToBaseUnit(q1.getValue()) - q2.getUnit().convertToBaseUnit(q2.getValue());

        double resultValue = q1.getUnit().convertFromBaseUnit(base);

        QuantityModel<IMeasurable> result = new QuantityModel<>(resultValue, q1.getUnit());

        repository.save(new QuantityMeasurementEntity(q1, q2, "SUBTRACT", result));

        return convertToDTO(result);
    }

    @Override
    public double divide(QuantityDTO first, QuantityDTO second) {
        QuantityModel<IMeasurable> q1 = convertToModel(first);
        QuantityModel<IMeasurable> q2 = convertToModel(second);

        validateType(q1, q2);

        double base1 = q1.getUnit().convertToBaseUnit(q1.getValue());
        double base2 = q2.getUnit().convertToBaseUnit(q2.getValue());

        if (base2 == 0) throw new QuantityMeasurementException("Division by zero");

        double result = base1 / base2;

        repository.save(new QuantityMeasurementEntity(q1, q2, "DIVIDE", String.valueOf(result)));

        return result;
    }

    private void validateType(QuantityModel<IMeasurable> q1, QuantityModel<IMeasurable> q2) {
        if (!q1.getUnit().getMeasurementType().equals(q2.getUnit().getMeasurementType())) {
            throw new QuantityMeasurementException("Operation not allowed with diffrent category!");
        }
    }
}