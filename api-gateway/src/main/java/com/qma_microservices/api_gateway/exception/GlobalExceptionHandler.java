package com.qma_microservices.api_gateway.exception;

import com.qma_microservices.api_gateway.ApiGatewayApplication;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;

class ErrorResponse{
    public LocalDateTime timeStamp;
    public int status;
    public String error;
    public String message;
    public String path;
}

@Slf4j
@RequiredArgsConstructor
@RestControllerAdvice
public class GlobalExceptionHandler {
    private final ApiGatewayApplication application;
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> handleException(RuntimeException ex) {
        log.info(ex.getMessage());
        ErrorResponse errorResponse = new ErrorResponse();

        errorResponse.timeStamp = LocalDateTime.now();
        errorResponse.status = HttpStatus.BAD_REQUEST.value();
        errorResponse.error = "Quantity measurement error";
        errorResponse.message = ex.getMessage();
//        errorResponse.path = request.getDescription(false).replace("uri=", "");

        return ResponseEntity.badRequest().body(errorResponse);
    }
}
