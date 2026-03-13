package com.apps.quantitymeasurement.entity;

/**
 * Data Transfer Object used for transferring quantity data
 * between Controller and Service layers.
 */
public class QuantityDTO {
    private double value;
    private IMeasurableUnit unit;

    public QuantityDTO(double value, IMeasurableUnit unit) {
        this.value = value;
        this.unit = unit;
    }

    public double getValue() {
        return value;
    }

    public IMeasurableUnit getUnit() {
        return unit;
    }

    // Interface representing measurable units for DTO layer
    public interface IMeasurableUnit {
        String getUnitName();
        String getMeasurementType();
    }

    // Length Units
    public enum LengthUnit implements IMeasurableUnit {
        FEET,
        INCHES,
        YARDS,
        CENTIMETERS;

        @Override
        public String getUnitName() {
            return this.name();
        }

        @Override
        public String getMeasurementType() {
            return this.getClass().getSimpleName();
        }
    }

    // Weight Units
    public enum WeightUnit implements IMeasurableUnit {
        MILLIGRAM,
        GRAM,
        KILOGRAM,
        POUND,
        TONNE;

        @Override
        public String getUnitName() {
            return this.name();
        }

        @Override
        public String getMeasurementType() {
            return this.getClass().getSimpleName();
        }
    }

    // Volume Units
    public enum VolumeUnit implements IMeasurableUnit {
        LITRE,
        MILLILITRE,
        GALLON;

        @Override
        public String getUnitName() {
            return this.name();
        }

        @Override
        public String getMeasurementType() {
            return this.getClass().getSimpleName();
        }
    }

    // Temperature Units
    public enum TemperatureUnit implements IMeasurableUnit {
        CELSIUS,
        FAHRENHEIT;

        @Override
        public String getUnitName() {
            return this.name();
        }

        @Override
        public String getMeasurementType() {
            return this.getClass().getSimpleName();
        }
    }
}