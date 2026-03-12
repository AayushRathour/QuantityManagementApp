package com.apps.quantitymeasurement.entity;

import java.io.Serializable;

public class QuantityMeasurementEntity implements Serializable {

    private static final long serialVersionUID = 1L;

    private String operationType;
    private String operand1;
    private String operand2;
    private String result;
    private boolean error;
    private String errorMessage;

    public QuantityMeasurementEntity(String operationType, String operand1, String operand2, String result) {
        this.operationType = operationType;
        this.operand1 = operand1;
        this.operand2 = operand2;
        this.result = result;
        this.error = false;
    }

    public QuantityMeasurementEntity(String operationType, String operand1, String result) {
        this.operationType = operationType;
        this.operand1 = operand1;
        this.result = result;
        this.error = false;
    }

    public QuantityMeasurementEntity(String operationType, String operand1, String operand2, String errorMessage, boolean error) {
        this.operationType = operationType;
        this.operand1 = operand1;
        this.operand2 = operand2;
        this.errorMessage = errorMessage;
        this.error = error;
    }

    public String getOperationType() {
        return operationType;
    }

    public String getOperand1() {
        return operand1;
    }

    public String getOperand2() {
        return operand2;
    }

    public String getResult() {
        return result;
    }

    public boolean isError() {
        return error;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    @Override
    public String toString() {
        if (error) {
            return "OperationType=" + operationType +
                    ", operand1=" + operand1 +
                    ", operand2=" + operand2 +
                    ", errorMessage=" + errorMessage;
        }

        return "OperationType=" + operationType +
                ", operand1=" + operand1 +
                ", operand2=" + operand2 +
                ", result=" + result;
    }
}