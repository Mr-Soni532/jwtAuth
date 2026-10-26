package com.demo.jwtauth.exception;

import org.springframework.http.HttpStatus;

/** Custom exception carrying the HTTP status to return. */
public class ApiException extends RuntimeException {
    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
