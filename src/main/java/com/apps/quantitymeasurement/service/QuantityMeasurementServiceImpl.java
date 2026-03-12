package com.apps.quantitymeasurement.service;

import com.apps.quantitymeasurement.IMeasurable;
import com.apps.quantitymeasurement.LengthUnit;
import com.apps.quantitymeasurement.Quantity;
import com.apps.quantitymeasurement.TemperatureUnit;
import com.apps.quantitymeasurement.VolumeUnit;
import com.apps.quantitymeasurement.WeightUnit;
import com.apps.quantitymeasurement.dto.QuantityDTO;
import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.exception.QuantityMeasurementException;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;

public class QuantityMeasurementServiceImpl implements IQuantityMeasurementService {

    private final IQuantityMeasurementRepository repository;

    public QuantityMeasurementServiceImpl(IQuantityMeasurementRepository repository) {
        if (repository == null) {
            throw new IllegalArgumentException("Repository cannot be null");
        }
        this.repository = repository;
    }

    private IMeasurable parseUnit(String unitName) {
        if (unitName == null || unitName.isBlank()) {
            throw new QuantityMeasurementException("Unit cannot be null or blank");
        }

        try {
            return LengthUnit.valueOf(unitName.toUpperCase());
        } catch (IllegalArgumentException ignored) {}

        try {
            return WeightUnit.valueOf(unitName.toUpperCase());
        } catch (IllegalArgumentException ignored) {}

        try {
            return VolumeUnit.valueOf(unitName.toUpperCase());
        } catch (IllegalArgumentException ignored) {}

        try {
            return TemperatureUnit.valueOf(unitName.toUpperCase());
        } catch (IllegalArgumentException ignored) {}

        throw new QuantityMeasurementException("Invalid unit: " + unitName);
    }

    private void validateSameCategory(IMeasurable unit1, IMeasurable unit2) {
        if (!unit1.getClass().equals(unit2.getClass())) {
            throw new QuantityMeasurementException("Cross-category operations not allowed");
        }
    }

    @SuppressWarnings("unchecked")
    private <U extends IMeasurable> Quantity<U> buildQuantity(QuantityDTO dto) {
        if (dto == null) {
            throw new QuantityMeasurementException("QuantityDTO cannot be null");
        }

        IMeasurable measurable = parseUnit(dto.getUnit());
        return new Quantity<>(dto.getValue(), (U) measurable);
    }

    private QuantityDTO toDTO(Quantity<?> quantity) {
        return new QuantityDTO(quantity.getValue(), quantity.getUnit().toString());
    }

    @Override
    public boolean compare(QuantityDTO quantity1, QuantityDTO quantity2) {

        try {

            Quantity<?> q1 = buildQuantity(quantity1);
            Quantity<?> q2 = buildQuantity(quantity2);

            validateSameCategory(q1.getUnit(), q2.getUnit());

            boolean result = q1.equals(q2);

            repository.save(new QuantityMeasurementEntity(
                    "COMPARE",
                    quantity1.toString(),
                    quantity2.toString(),
                    String.valueOf(result)
            ));

            return result;

        } catch (Exception e) {

            repository.save(new QuantityMeasurementEntity(
                    "COMPARE",
                    String.valueOf(quantity1),
                    String.valueOf(quantity2),
                    e.getMessage(),
                    true
            ));

            throw new QuantityMeasurementException("Comparison failed: " + e.getMessage(), e);
        }
    }

    @Override
    public QuantityDTO convert(QuantityDTO sourceQuantity, String targetUnit) {

        try {

            Quantity<?> source = buildQuantity(sourceQuantity);
            IMeasurable target = parseUnit(targetUnit);

            validateSameCategory(source.getUnit(), target);

            double converted;

            if (target instanceof LengthUnit lengthUnit) {

                converted = ((Quantity<LengthUnit>) source).convertTo(lengthUnit);

            } else if (target instanceof WeightUnit weightUnit) {

                converted = ((Quantity<WeightUnit>) source).convertTo(weightUnit);

            } else if (target instanceof VolumeUnit volumeUnit) {

                converted = ((Quantity<VolumeUnit>) source).convertTo(volumeUnit);

            } else if (target instanceof TemperatureUnit temperatureUnit) {

                converted = ((Quantity<TemperatureUnit>) source).convertTo(temperatureUnit);

            } else {

                throw new QuantityMeasurementException("Unsupported target unit");

            }

            QuantityDTO result = toDTO(converted);

            repository.save(new QuantityMeasurementEntity(
                    "CONVERT",
                    sourceQuantity.toString(),
                    result.toString()
            ));

            return result;

        } catch (Exception e) {

            repository.save(new QuantityMeasurementEntity(
                    "CONVERT",
                    String.valueOf(sourceQuantity),
                    targetUnit,
                    e.getMessage(),
                    true
            ));

            throw new QuantityMeasurementException("Conversion failed: " + e.getMessage(), e);
        }
    }

    private QuantityDTO toDTO(double converted) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
    public QuantityDTO add(QuantityDTO quantity1, QuantityDTO quantity2) {

        try {

            Quantity<?> q1 = buildQuantity(quantity1);
            Quantity<?> q2 = buildQuantity(quantity2);

            validateSameCategory(q1.getUnit(), q2.getUnit());

            Quantity<?> result;

            if (q1.getUnit() instanceof LengthUnit) {

                result = ((Quantity<LengthUnit>) q1).add((Quantity<LengthUnit>) q2);

            } else if (q1.getUnit() instanceof WeightUnit) {

                result = ((Quantity<WeightUnit>) q1).add((Quantity<WeightUnit>) q2);

            } else if (q1.getUnit() instanceof VolumeUnit) {

                result = ((Quantity<VolumeUnit>) q1).add((Quantity<VolumeUnit>) q2);

            } else if (q1.getUnit() instanceof TemperatureUnit) {

                result = ((Quantity<TemperatureUnit>) q1).add((Quantity<TemperatureUnit>) q2);

            } else {

                throw new QuantityMeasurementException("Unsupported measurement type for addition");

            }

            QuantityDTO resultDTO = toDTO(result);

            repository.save(new QuantityMeasurementEntity(
                    "ADD",
                    quantity1.toString(),
                    quantity2.toString(),
                    resultDTO.toString()
            ));

            return resultDTO;

        } catch (Exception e) {

            repository.save(new QuantityMeasurementEntity(
                    "ADD",
                    String.valueOf(quantity1),
                    String.valueOf(quantity2),
                    e.getMessage(),
                    true
            ));

            throw new QuantityMeasurementException("Addition failed: " + e.getMessage(), e);
        }
    }

    @Override
    public QuantityDTO subtract(QuantityDTO quantity1, QuantityDTO quantity2) {

        try {

            Quantity<?> q1 = buildQuantity(quantity1);
            Quantity<?> q2 = buildQuantity(quantity2);

            validateSameCategory(q1.getUnit(), q2.getUnit());

            Quantity<?> result;

            if (q1.getUnit() instanceof LengthUnit) {

                result = ((Quantity<LengthUnit>) q1).subtract((Quantity<LengthUnit>) q2);

            } else if (q1.getUnit() instanceof WeightUnit) {

                result = ((Quantity<WeightUnit>) q1).subtract((Quantity<WeightUnit>) q2);

            } else if (q1.getUnit() instanceof VolumeUnit) {

                result = ((Quantity<VolumeUnit>) q1).subtract((Quantity<VolumeUnit>) q2);

            } else if (q1.getUnit() instanceof TemperatureUnit) {

                result = ((Quantity<TemperatureUnit>) q1).subtract((Quantity<TemperatureUnit>) q2);

            } else {

                throw new QuantityMeasurementException("Unsupported measurement type for subtraction");

            }

            QuantityDTO resultDTO = toDTO(result);

            repository.save(new QuantityMeasurementEntity(
                    "SUBTRACT",
                    quantity1.toString(),
                    quantity2.toString(),
                    resultDTO.toString()
            ));

            return resultDTO;

        } catch (Exception e) {

            repository.save(new QuantityMeasurementEntity(
                    "SUBTRACT",
                    String.valueOf(quantity1),
                    String.valueOf(quantity2),
                    e.getMessage(),
                    true
            ));

            throw new QuantityMeasurementException("Subtraction failed: " + e.getMessage(), e);
        }
    }

    @Override
    public double divide(QuantityDTO quantity1, QuantityDTO quantity2) {

        try {

            Quantity<?> q1 = buildQuantity(quantity1);
            Quantity<?> q2 = buildQuantity(quantity2);

            validateSameCategory(q1.getUnit(), q2.getUnit());

            double result;

            if (q1.getUnit() instanceof LengthUnit) {

                result = ((Quantity<LengthUnit>) q1).divide((Quantity<LengthUnit>) q2);

            } else if (q1.getUnit() instanceof WeightUnit) {

                result = ((Quantity<WeightUnit>) q1).divide((Quantity<WeightUnit>) q2);

            } else if (q1.getUnit() instanceof VolumeUnit) {

                result = ((Quantity<VolumeUnit>) q1).divide((Quantity<VolumeUnit>) q2);

            } else if (q1.getUnit() instanceof TemperatureUnit) {

                result = ((Quantity<TemperatureUnit>) q1).divide((Quantity<TemperatureUnit>) q2);

            } else {

                throw new QuantityMeasurementException("Unsupported measurement type for division");

            }

            repository.save(new QuantityMeasurementEntity(
                    "DIVIDE",
                    quantity1.toString(),
                    quantity2.toString(),
                    String.valueOf(result)
            ));

            return result;

        } catch (Exception e) {

            repository.save(new QuantityMeasurementEntity(
                    "DIVIDE",
                    String.valueOf(quantity1),
                    String.valueOf(quantity2),
                    e.getMessage(),
                    true
            ));

            throw new QuantityMeasurementException("Division failed: " + e.getMessage(), e);
        }
    }
}