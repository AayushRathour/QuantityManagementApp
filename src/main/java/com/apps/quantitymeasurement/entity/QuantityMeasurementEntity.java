package com.apps.quantitymeasurement.entity;

import java.io.Serializable;
import com.apps.quantitymeasurement.unit.IMeasurable;

public class QuantityMeasurementEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    // Operand 1
    public double thisValue;
    public String thisUnit;
    public String thisMeasurementType;

    // Operand 2
    public double thatValue;
    public String thatUnit;
    public String thatMeasurementType;

    // Operation type
    public String operation;

    // Result values
    public double resultValue;
    public String resultUnit;
    public String resultMeasurementType;

    // For comparison results
    public String resultString;

    // Error handling
    public boolean isError;
    public String errorMessage;

    public QuantityMeasurementEntity(
            QuantityModel<IMeasurable> thisQuantity,
            QuantityModel<IMeasurable> thatQuantity,
            String operation) {

        if (thisQuantity != null) {
            this.thisValue = thisQuantity.getValue();
            this.thisUnit = thisQuantity.getUnit().getUnitName();
            this.thisMeasurementType = thisQuantity.getUnit().getMeasurementType();
        }

        if (thatQuantity != null) {
            this.thatValue = thatQuantity.getValue();
            this.thatUnit = thatQuantity.getUnit().getUnitName();
            this.thatMeasurementType = thatQuantity.getUnit().getMeasurementType();
        }

        this.operation = operation;
    }

    // Constructor
    public QuantityMeasurementEntity(
            QuantityModel<IMeasurable> thisQuantity,
            QuantityModel<IMeasurable> thatQuantity,
            String operation,
            String result) {

        this(thisQuantity, thatQuantity, operation);
        this.resultString = result;
    }

    
    public QuantityMeasurementEntity(
            QuantityModel<IMeasurable> thisQuantity,
            QuantityModel<IMeasurable> thatQuantity,
            String operation,
            QuantityModel<IMeasurable> result) {

        this(thisQuantity, thatQuantity, operation);

        if (result != null) {
            this.resultValue = result.getValue();
            this.resultUnit = result.getUnit().getUnitName();
            this.resultMeasurementType = result.getUnit().getMeasurementType();
        }
    }

    public QuantityMeasurementEntity(
            QuantityModel<IMeasurable> thisQuantity,
            QuantityModel<IMeasurable> thatQuantity,
            String operation,
            String errorMessage,
            boolean isError) {

        this(thisQuantity, thatQuantity, operation);
        this.errorMessage = errorMessage;
        this.isError = isError;
    }
}