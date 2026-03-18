package com.apps.quantitymeasurement.repository;

import java.sql.*;
import java.util.*;
import java.util.logging.Logger;

import com.apps.quantitymeasurement.entity.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.exception.DatabaseException;
import com.apps.quantitymeasurement.util.ConnectionPool;

public class QuantityMeasurementDatabaseRepository implements IQuantityMeasurementRepository {
    private static final Logger logger = Logger.getLogger(QuantityMeasurementDatabaseRepository.class.getName());

    private static QuantityMeasurementDatabaseRepository instance;

    private static final String INSERT_QUERY =
            "INSERT INTO quantity_measurement_entity " +
                    "(this_value, this_unit, this_measurement_type, that_value, that_unit, " +
                    "that_measurement_type, operation, result_value, result_unit, " +
                    "result_measurement_type, result_string, is_error, error_message, " +
                    "created_at, updated_at) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())";

    private static final String SELECT_ALL_QUERY = "SELECT * FROM quantity_measurement_entity ORDER BY created_at DESC";

    private static final String SELECT_BY_OPERATION = "SELECT * FROM quantity_measurement_entity WHERE operation = ? ORDER BY created_at DESC";

    private static final String SELECT_BY_MEASUREMENT_TYPE = "SELECT * FROM quantity_measurement_entity WHERE this_measurement_type = ? ORDER BY created_at DESC";

    private static final String DELETE_ALL_QUERY = "DELETE FROM quantity_measurement_entity";

    private static final String COUNT_QUERY = "SELECT COUNT(*) FROM quantity_measurement_entity";

    private ConnectionPool connectionPool;

    private QuantityMeasurementDatabaseRepository() {

        try {
            connectionPool = ConnectionPool.getInstance();
            initializeDatabase();
        } 
        catch (SQLException e) {
            throw DatabaseException.connectionFailed("Initializing connection pool", e);
        }
    }

    private void initializeDatabase() {
        String createTable =
                "CREATE TABLE IF NOT EXISTS quantity_measurement_entity (" +
                        "id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                        "this_value DOUBLE NOT NULL," +
                        "this_unit VARCHAR(50) NOT NULL," +
                        "this_measurement_type VARCHAR(50) NOT NULL," +
                        "that_value DOUBLE," +
                        "that_unit VARCHAR(50)," +
                        "that_measurement_type VARCHAR(50)," +
                        "operation VARCHAR(20) NOT NULL," +
                        "result_value DOUBLE," +
                        "result_unit VARCHAR(50)," +
                        "result_measurement_type VARCHAR(50)," +
                        "result_string VARCHAR(255)," +
                        "is_error BOOLEAN DEFAULT FALSE," +
                        "error_message VARCHAR(500)," +
                        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                        "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" +
                        ")";

        Connection conn = null;
        Statement stmt = null;

        try {
            conn = connectionPool.getConnection();
            stmt = conn.createStatement();
            stmt.execute(createTable);
        } 
        catch (SQLException e) {
            logger.severe("Error initializing database: " + e.getMessage());
        } 
        finally {
            closeResources(stmt, conn);
        }
    }

    public static synchronized QuantityMeasurementDatabaseRepository getInstance() {
        if (instance == null) instance = new QuantityMeasurementDatabaseRepository();

        return instance;
    }

    @Override
    public void save(QuantityMeasurementEntity entity) {
        Connection conn = null;
        PreparedStatement stmt = null;

        try {

            conn = connectionPool.getConnection();
            stmt = conn.prepareStatement(INSERT_QUERY);

            stmt.setDouble(1, entity.thisValue);
            stmt.setString(2, entity.thisUnit);
            stmt.setString(3, entity.thisMeasurementType);
            stmt.setDouble(4, entity.thatValue);
            stmt.setString(5, entity.thatUnit);
            stmt.setString(6, entity.thatMeasurementType);
            stmt.setString(7, entity.operation);
            stmt.setDouble(8, entity.resultValue);
            stmt.setString(9, entity.resultUnit);
            stmt.setString(10, entity.resultMeasurementType);
            stmt.setString(11, entity.resultString);
            stmt.setBoolean(12, entity.isError);
            stmt.setString(13, entity.errorMessage);

            stmt.executeUpdate();
        } 
        catch (SQLException e) {
            throw DatabaseException.queryFailed(INSERT_QUERY, e);
        } 
        finally {
            closeResources(stmt, conn);
        }
    }

    @Override
    public List<QuantityMeasurementEntity> getAllMeasurements() {

        List<QuantityMeasurementEntity> list = new ArrayList<>();

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = connectionPool.getConnection();
            stmt = conn.createStatement();
            rs = stmt.executeQuery(SELECT_ALL_QUERY);

            while (rs.next()) {
                list.add(mapResultSetToEntity(rs));
            }

        } 
        catch (SQLException e) {
            throw DatabaseException.queryFailed(SELECT_ALL_QUERY, e);
        }
        finally {
            closeResources(rs, stmt, conn);
        }

        return list;
    }

    public List<QuantityMeasurementEntity> getMeasurementsByOperation(String operation) {
        List<QuantityMeasurementEntity> list = new ArrayList<>();

        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            conn = connectionPool.getConnection();
            stmt = conn.prepareStatement(SELECT_BY_OPERATION);
            stmt.setString(1, operation);

            rs = stmt.executeQuery();

            while (rs.next()) {
                list.add(mapResultSetToEntity(rs));
            }
        } 
        catch (SQLException e) {
            throw DatabaseException.queryFailed(SELECT_BY_OPERATION, e);
        } 
        finally {
            closeResources(rs, stmt, conn);
        }

        return list;
    }

    public List<QuantityMeasurementEntity> getMeasurementsByType(String measurementType) {

        List<QuantityMeasurementEntity> list = new ArrayList<>();

        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {

            conn = connectionPool.getConnection();
            stmt = conn.prepareStatement(SELECT_BY_MEASUREMENT_TYPE);
            stmt.setString(1, measurementType);

            rs = stmt.executeQuery();

            while (rs.next()) {
                list.add(mapResultSetToEntity(rs));
            }

        } catch (SQLException e) {

            throw DatabaseException.queryFailed(SELECT_BY_MEASUREMENT_TYPE, e);

        } finally {

            closeResources(rs, stmt, conn);
        }

        return list;
    }

    public int getTotalCount() {

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {

            conn = connectionPool.getConnection();
            stmt = conn.createStatement();
            rs = stmt.executeQuery(COUNT_QUERY);

            if (rs.next()) {
                return rs.getInt(1);
            }

        } catch (SQLException e) {

            throw DatabaseException.queryFailed(COUNT_QUERY, e);

        } finally {

            closeResources(rs, stmt, conn);
        }

        return 0;
    }

    public void deleteAll() {

        Connection conn = null;
        Statement stmt = null;

        try {

            conn = connectionPool.getConnection();
            stmt = conn.createStatement();
            stmt.executeUpdate(DELETE_ALL_QUERY);

        } catch (SQLException e) {

            throw DatabaseException.queryFailed(DELETE_ALL_QUERY, e);

        } finally {

            closeResources(stmt, conn);
        }
    }

    public String getPoolStatistics() {

        return connectionPool.toString();
    }

    public void releaseResources() {

        connectionPool.closeAll();
    }

    private QuantityMeasurementEntity mapResultSetToEntity(ResultSet rs) throws SQLException {

        QuantityMeasurementEntity entity = new QuantityMeasurementEntity(null, null, null);

        entity.thisValue = rs.getDouble("this_value");
        entity.thisUnit = rs.getString("this_unit");
        entity.thisMeasurementType = rs.getString("this_measurement_type");
        entity.thatValue = rs.getDouble("that_value");
        entity.thatUnit = rs.getString("that_unit");
        entity.thatMeasurementType = rs.getString("that_measurement_type");
        entity.operation = rs.getString("operation");
        entity.resultValue = rs.getDouble("result_value");
        entity.resultUnit = rs.getString("result_unit");
        entity.resultMeasurementType = rs.getString("result_measurement_type");
        entity.resultString = rs.getString("result_string");
        entity.isError = rs.getBoolean("is_error");
        entity.errorMessage = rs.getString("error_message");

        return entity;
    }

    private void closeResources(ResultSet rs, Statement stmt, Connection conn) {

        try {

            if (rs != null) rs.close();
            if (stmt != null) stmt.close();

        } catch (SQLException ignored) {
        }

        if (conn != null) {
            connectionPool.releaseConnection(conn);
        }
    }

    private void closeResources(Statement stmt, Connection conn) {

        try {

            if (stmt != null) stmt.close();

        } catch (SQLException ignored) {
        }

        if (conn != null) {
            connectionPool.releaseConnection(conn);
        }
    }

    public static void main(String[] args) {

        QuantityMeasurementDatabaseRepository repo =
                QuantityMeasurementDatabaseRepository.getInstance();

        System.out.println("Total records: " + repo.getTotalCount());
        System.out.println("Pool stats: " + repo.getPoolStatistics());
    }
}