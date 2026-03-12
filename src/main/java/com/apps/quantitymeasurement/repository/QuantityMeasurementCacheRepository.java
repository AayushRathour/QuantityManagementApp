package com.apps.quantitymeasurement.repository;

import java.util.ArrayList;
import java.util.List;

import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;

public class QuantityMeasurementCacheRepository implements IQuantityMeasurementRepository {

    private static QuantityMeasurementCacheRepository instance;
    private final List<QuantityMeasurementEntity> measurementCache;

    private QuantityMeasurementCacheRepository() {
        measurementCache = new ArrayList<>();
    }

    public static QuantityMeasurementCacheRepository getInstance() {
        if (instance == null) {
            instance = new QuantityMeasurementCacheRepository();
        }
        return instance;
    }

    @Override
    public void save(QuantityMeasurementEntity entity) {
        measurementCache.add(entity);
    }

    @Override
    public List<QuantityMeasurementEntity> findAll() {
        return new ArrayList<>(measurementCache);
    }
}