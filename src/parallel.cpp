#include "parallel.h"

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}