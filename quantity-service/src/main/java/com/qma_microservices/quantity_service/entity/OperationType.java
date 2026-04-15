package com.qma_microservices.quantity_service.entity;

public enum OperationType {
    ADD,
    SUBTRACT,
    MULTIPLY,
    DIVIDE,
    COMPARE,
    CONVERT;

    public String getDisplayName() {
        return this.name().toLowerCase();
    }
}