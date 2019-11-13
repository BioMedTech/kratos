// Code generated by go-swagger; DO NOT EDIT.

package public

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/ory/kratos/sdk/go/kratos/models"
)

// GetRegistrationRequestReader is a Reader for the GetRegistrationRequest structure.
type GetRegistrationRequestReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetRegistrationRequestReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetRegistrationRequestOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 404:
		result := NewGetRegistrationRequestNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetRegistrationRequestInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetRegistrationRequestOK creates a GetRegistrationRequestOK with default headers values
func NewGetRegistrationRequestOK() *GetRegistrationRequestOK {
	return &GetRegistrationRequestOK{}
}

/*GetRegistrationRequestOK handles this case with default header values.

registrationRequest
*/
type GetRegistrationRequestOK struct {
	Payload *models.RegistrationRequest
}

func (o *GetRegistrationRequestOK) Error() string {
	return fmt.Sprintf("[GET /auth/browser/requests/registration][%d] getRegistrationRequestOK  %+v", 200, o.Payload)
}

func (o *GetRegistrationRequestOK) GetPayload() *models.RegistrationRequest {
	return o.Payload
}

func (o *GetRegistrationRequestOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RegistrationRequest)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRegistrationRequestNotFound creates a GetRegistrationRequestNotFound with default headers values
func NewGetRegistrationRequestNotFound() *GetRegistrationRequestNotFound {
	return &GetRegistrationRequestNotFound{}
}

/*GetRegistrationRequestNotFound handles this case with default header values.

genericError
*/
type GetRegistrationRequestNotFound struct {
	Payload *models.GenericError
}

func (o *GetRegistrationRequestNotFound) Error() string {
	return fmt.Sprintf("[GET /auth/browser/requests/registration][%d] getRegistrationRequestNotFound  %+v", 404, o.Payload)
}

func (o *GetRegistrationRequestNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *GetRegistrationRequestNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRegistrationRequestInternalServerError creates a GetRegistrationRequestInternalServerError with default headers values
func NewGetRegistrationRequestInternalServerError() *GetRegistrationRequestInternalServerError {
	return &GetRegistrationRequestInternalServerError{}
}

/*GetRegistrationRequestInternalServerError handles this case with default header values.

genericError
*/
type GetRegistrationRequestInternalServerError struct {
	Payload *models.GenericError
}

func (o *GetRegistrationRequestInternalServerError) Error() string {
	return fmt.Sprintf("[GET /auth/browser/requests/registration][%d] getRegistrationRequestInternalServerError  %+v", 500, o.Payload)
}

func (o *GetRegistrationRequestInternalServerError) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *GetRegistrationRequestInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
