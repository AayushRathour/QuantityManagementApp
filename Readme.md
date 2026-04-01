# Quantity Measurement Backend

This is a Spring Boot based backend application that provides APIs for user authentication and quantity measurement operations such as comparison, conversion, and arithmetic.

## Overview

The backend handles user login and signup using JWT authentication and provides secure APIs to perform operations on different measurement types like length, weight, temperature, and volume.

## Features

- User authentication using JWT
- Secure API endpoints
- Measurement operations:
  - Compare two quantities
  - Convert units
  - Add, subtract, and divide quantities
- Supports multiple measurement types:
  - Length
  - Weight
  - Temperature
  - Volume
- Stores and retrieves operation history
- Tracks and returns error cases

## Project Structure

- controller  
  Contains REST API endpoints for authentication and quantity operations

- service  
  Contains business logic for calculations and authentication

- repository  
  Handles database interaction using JPA

- entity  
  Represents database tables

- dto  
  Used for request and response data transfer

- config  
  Contains security configuration and JWT setup

- exception  
  Handles global and custom exceptions

## API Modules

Authentication:
- Signup
- Login

Quantity:
- Compare
- Convert
- Add
- Subtract
- Divide

History:
- Get history by type
- Get error history

## Security

- Uses JWT for authentication
- All quantity APIs require a valid token
- Token is passed in the Authorization header

## Configuration

The application uses MySQL as the database. Configure the following in application.properties:

- Database URL
- Username and password
- JWT secret key

## Running the Application

1. Build the project  
mvn clean install

2. Run the application  
mvn spring-boot:run

3. Server will start at  
http://localhost:8080

## Notes

- Units must match predefined enum values in backend
- Measurement type is required for all operations
- Backend is designed to work with Angular frontend
