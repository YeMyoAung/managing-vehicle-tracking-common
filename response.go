package common

import (
    "errors"
    "strings"

    "github.com/go-playground/validator/v10"
)

type Response struct {
    Success bool        `json:"success"`
    Message string      `json:"message"`
    Data    interface{} `json:"data"`
    Error   interface{} `json:"error"`
}

func DefaultSuccessResponse(data any, message string) *Response {
    return &Response{
        Success: true,
        Message: message,
        Data:    data,
        Error:   nil,
    }
}

func FormatValidationMessage(tag string) string {
    switch tag {
    case "required":
        return "This field is required"
    case "email":
        return "Invalid email"
    case "jwt":
        return "Malformed jwt"
    case "uuid":
        return "Invalid uuid format"
    case "bool":
        return "Invalid boolean value"
    }

    return ""
}

func DefaultErrorResponse(err error) *Response {
    response := &Response{
        Success: false,
        Message: err.Error(),
        Data:    nil,
    }
    var validationErrors validator.ValidationErrors

    customErrorsFormat := make(map[string]string)
    if errors.As(err, &validationErrors) {
        for _, field := range validationErrors {
            customErrorsFormat[strings.ToLower(field.Field())] = FormatValidationMessage(field.Tag())
        }
        response.Error = customErrorsFormat
    }

    return response
}
