#include "objectManagement.h"

CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phObject) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phNewObject) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ULONG_PTR pulSize) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(
	CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE_PTR phObject,
	CK_ULONG ulMaxObjectCount,
	CK_ULONG_PTR pulObjectCount) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(
	CK_SESSION_HANDLE hSession) {
	return CKR_FUNCTION_NOT_SUPPORTED;
}