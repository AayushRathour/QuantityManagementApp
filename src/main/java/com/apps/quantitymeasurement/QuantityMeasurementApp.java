package com.apps.quantitymeasurement;

import com.apps.quantitymeasurement.controller.QuantityMeasurementController;
import com.apps.quantitymeasurement.entity.QuantityDTO;
import com.apps.quantitymeasurement.repository.IQuantityMeasurementRepository;
import com.apps.quantitymeasurement.repository.QuantityMeasurementCacheRepository;
import com.apps.quantitymeasurement.service.IQuantityMeasurementService;
import com.apps.quantitymeasurement.service.QuantityMeasurementServiceImpl;

public class QuantityMeasurementApp {

    public static void main(String[] args) {
    	IQuantityMeasurementRepository repository = QuantityMeasurementCacheRepository.getInstance();

        IQuantityMeasurementService service = new QuantityMeasurementServiceImpl(repository);

        QuantityMeasurementController controller = new QuantityMeasurementController(service);

        QuantityDTO length1 = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO length2 = new QuantityDTO(120, QuantityDTO.LengthUnit.INCHES);
        controller.performCompare(length1, length2);

        QuantityDTO weight = new QuantityDTO(1, QuantityDTO.WeightUnit.KILOGRAM);
        controller.performConvert(weight, "GRAM");

        QuantityDTO feet = new QuantityDTO(10, QuantityDTO.LengthUnit.FEET);
        QuantityDTO inches = new QuantityDTO(6, QuantityDTO.LengthUnit.INCHES);
        controller.performAdd(feet, inches);

        controller.performSubtract(feet, inches);

        QuantityDTO feet20 = new QuantityDTO(20, QuantityDTO.LengthUnit.FEET);
        QuantityDTO feet5 = new QuantityDTO(5, QuantityDTO.LengthUnit.FEET);
        controller.performDivide(feet20, feet5);

        QuantityDTO temp1 = new QuantityDTO(0, QuantityDTO.TemperatureUnit.CELSIUS);
        QuantityDTO temp2 = new QuantityDTO(32, QuantityDTO.TemperatureUnit.FAHRENHEIT);

        controller.performCompare(temp1, temp2);
    }
}