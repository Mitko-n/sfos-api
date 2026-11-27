"""Tests for SFOS exceptions and unified error processing helpers."""

from sfos_api import (
    AuthenticationError,
    AuthorizationError,
    BadGatewayError,
    BadRequestError,
    ConflictError,
    GatewayTimeoutError,
    InternalServerError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
    SFOSApiError,
    SFOSApiErrorInfo,
    SFOSConnectionError,
    SFOSTimeoutError,
    UnexpectedError,
    UnprocessableEntityError,
    parse_error,
    parse_errors,
)


def test_exception_attributes():
    err = SFOSApiError("Test error", status_code=400, error="invalid_request", code=101, response_body={"msg": "fail"})
    assert str(err) == "Test error"
    assert err.status_code == 400
    assert err.error == "invalid_request"
    assert err.code == 101
    assert err.response_body == {"msg": "fail"}


def test_exception_subclasses():
    assert issubclass(BadRequestError, SFOSApiError)
    assert issubclass(AuthenticationError, SFOSApiError)
    assert issubclass(AuthorizationError, SFOSApiError)
    assert issubclass(NotFoundError, SFOSApiError)
    assert issubclass(ConflictError, SFOSApiError)
    assert issubclass(UnprocessableEntityError, SFOSApiError)
    assert issubclass(RateLimitError, SFOSApiError)
    assert issubclass(InternalServerError, SFOSApiError)
    assert issubclass(UnexpectedError, InternalServerError)
    assert issubclass(BadGatewayError, InternalServerError)
    assert issubclass(ServiceUnavailableError, InternalServerError)
    assert issubclass(GatewayTimeoutError, InternalServerError)
    assert issubclass(SFOSConnectionError, SFOSApiError)
    assert issubclass(SFOSTimeoutError, SFOSApiError)


def test_parse_error_from_sfos_api_error():
    err = NotFoundError("Zone not found.", status_code=404, error="notFound", code=404, response_body={"id": "LAN"})
    info = parse_error(err)

    assert isinstance(info, SFOSApiErrorInfo)
    assert info.message == "Zone not found."
    assert info.error == "notFound"
    assert info.code == 404
    assert info.status_code == 404
    assert info.resource_id == "LAN"
    assert "[HTTP 404]" in str(info)
    assert "notFound:" in str(info)

    # Test error_info property on exception
    assert err.error_info == info
    assert err.error_info.to_dict() == {
        "error": "notFound",
        "message": "Zone not found.",
        "code": 404,
        "status_code": 404,
        "resource_id": "LAN",
        "details": {"id": "LAN"},
    }


def test_parse_error_from_dict():
    # Direct error dictionary
    payload = {
        "error": "badRequest",
        "message": "Invalid IP address provided.",
        "code": 400,
    }
    info = parse_error(payload)
    assert info.error == "badRequest"
    assert info.message == "Invalid IP address provided."
    assert info.code == 400
    assert info.status_code == 400


def test_parse_errors_from_batch_response():
    # Batch response with items and errors
    batch_resp = {
        "items": [{"id": "rule-1"}],
        "errors": [
            {"id": "rule-2", "error": "inUse", "message": "Rule in use", "code": 409},
            {"id": "rule-3", "error": "notFound", "message": "Rule not found", "code": 404},
        ],
    }
    errors = parse_errors(batch_resp)
    assert len(errors) == 2
    assert errors[0].resource_id == "rule-2"
    assert errors[0].error == "inUse"
    assert errors[0].code == 409
    assert errors[1].resource_id == "rule-3"
    assert errors[1].error == "notFound"
    assert errors[1].code == 404

    # Single parse_error returns the first error from batch
    single_err = parse_error(batch_resp)
    assert single_err.resource_id == "rule-2"


def test_parse_errors_from_openapi_delete_batch_response():
    delete_resp = {
        "items": [
            {"item": {"name": "host-1"}, "deleted": True},
            {
                "item": {"name": "host-in-use"},
                "error": {"error": "conflict", "message": "Resource is in use.", "code": 409},
            },
            {"item": {"name": "host-failed"}, "deleted": False},
        ],
        "errors": {"total": 2},
    }
    errors = parse_errors(delete_resp)
    assert len(errors) == 2
    assert errors[0].resource_id == "host-in-use"
    assert errors[0].error == "conflict"
    assert errors[0].message == "Resource is in use."
    assert errors[0].code == 409
    assert errors[0].status_code == 409
    assert errors[1].resource_id == "host-failed"
    assert errors[1].error == "deleteFailed"

    first_err = parse_error(delete_resp)
    assert first_err == errors[0]

    # Batch response with zero failed items
    ok_resp = {
        "items": [{"item": {"name": "host-1"}, "deleted": True}],
        "errors": {"total": 0},
    }
    assert parse_errors(ok_resp) == []
    assert parse_error(ok_resp).message == "No errors in response"


def test_parse_error_from_generic_exception():
    exc = ValueError("Something bad happened")
    info = parse_error(exc)
    assert info.message == "Something bad happened"
    assert info.error == "ValueError"
    assert info.status_code is None


def test_parse_error_edge_cases():
    assert parse_error(None).message == "Unknown error"
    assert parse_errors(None) == []
    assert parse_errors([]) == []
    assert parse_error({"errors": []}).message == "No errors in response"
