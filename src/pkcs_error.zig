const pkcs = @import("pkcs.zig").pkcs;
const pcsc = @import("pcsc");

pub const PkcsError = error{
    Cancel,
    HostMemory,
    SlotIdInvalid,
    GeneralError,
    FunctionFailed,
    ArgumentsBad,
    NoEvent,
    AttributeSensitive,
    AttributeTypeInvalid,
    DeviceError,
    DeviceMemory,
    DeviceRemoved,
    KeyHandleInvalid,
    KeyTypeInconsistent,
    KeyFunctionNotPermitted,
    MechanismInvalid,
    ObjectHandleInvalid,
    OperationActive,
    OperationNotInitialized,
    PinIncorrect,
    PinInvalid,
    PinLenRange,
    PinLocked,
    SessionClosed,
    SessionHandleInvalid,
    TokenNoPresent,
    TokenNotRecognized,
    UserNotLoggedIn,
    CryptokiNotInitialized,
    DataLenRange,
};

pub fn toRV(err: PkcsError) pkcs.CK_RV {
    return switch (err) {
        PkcsError.Cancel => pkcs.CKR_CANCEL,
        PkcsError.HostMemory => pkcs.CKR_HOST_MEMORY,
        PkcsError.SlotIdInvalid => pkcs.CKR_SLOT_ID_INVALID,
        PkcsError.GeneralError => pkcs.CKR_GENERAL_ERROR,
        PkcsError.FunctionFailed => pkcs.CKR_FUNCTION_FAILED,
        PkcsError.ArgumentsBad => pkcs.CKR_ARGUMENTS_BAD,
        PkcsError.NoEvent => pkcs.CKR_NO_EVENT,
        PkcsError.AttributeSensitive => pkcs.CKR_ATTRIBUTE_SENSITIVE,
        PkcsError.AttributeTypeInvalid => pkcs.CKR_ATTRIBUTE_TYPE_INVALID,
        PkcsError.DeviceError => pkcs.CKR_DEVICE_ERROR,
        PkcsError.DeviceMemory => pkcs.CKR_DEVICE_MEMORY,
        PkcsError.DeviceRemoved => pkcs.CKR_DEVICE_REMOVED,
        PkcsError.KeyHandleInvalid => pkcs.CKR_KEY_HANDLE_INVALID,
        PkcsError.KeyTypeInconsistent => pkcs.CKR_KEY_TYPE_INCONSISTENT,
        PkcsError.KeyFunctionNotPermitted => pkcs.CKR_KEY_FUNCTION_NOT_PERMITTED,
        PkcsError.MechanismInvalid => pkcs.CKR_MECHANISM_INVALID,
        PkcsError.ObjectHandleInvalid => pkcs.CKR_OBJECT_HANDLE_INVALID,
        PkcsError.OperationActive => pkcs.CKR_OPERATION_ACTIVE,
        PkcsError.OperationNotInitialized => pkcs.CKR_OPERATION_NOT_INITIALIZED,
        PkcsError.PinIncorrect => pkcs.CKR_PIN_INCORRECT,
        PkcsError.PinInvalid => pkcs.CKR_PIN_INVALID,
        PkcsError.PinLenRange => pkcs.CKR_PIN_LEN_RANGE,
        PkcsError.PinLocked => pkcs.CKR_PIN_LOCKED,
        PkcsError.SessionClosed => pkcs.CKR_SESSION_CLOSED,
        PkcsError.SessionHandleInvalid => pkcs.CKR_SESSION_HANDLE_INVALID,
        PkcsError.TokenNoPresent => pkcs.CKR_TOKEN_NOT_PRESENT,
        PkcsError.TokenNotRecognized => pkcs.CKR_TOKEN_NOT_RECOGNIZED,
        PkcsError.UserNotLoggedIn => pkcs.CKR_USER_NOT_LOGGED_IN,
        PkcsError.CryptokiNotInitialized => pkcs.CKR_CRYPTOKI_NOT_INITIALIZED,
        PkcsError.DataLenRange => pkcs.CKR_DATA_LEN_RANGE,
    };
}

pub fn formPCSC(err: anyerror) PkcsError {
    return switch (err) {
        pcsc.Err.NoSmartCard => PkcsError.TokenNoPresent,
        pcsc.Err.NoMemory => PkcsError.HostMemory,
        else => PkcsError.DeviceError,
    };
}
