import ida_bytes
import idaapi
import idc
import ida_search
import idautils
import ida_funcs
import ida_hexrays
import ida_entry
import ida_xref
import ida_typeinf
import re
import os

"""
See https://github.com/VoidSec/DriverBuddyReloaded
Script to automatically identify WDF function pointers
Inspired by http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html
Originally by Nicolas Guigo
Modified by Braden Hollembaek, Adam Pond and Paolo Stagno
"""


WDFFUNCTIONS_STRUCT_NAME = "WDFFUNCTIONS"
WDF_DRIVER_CONFIG_STRUCT_NAME = "_WDF_DRIVER_CONFIG"
UNICODE_STRING_STRUCT_NAME = "_UNICODE_STRING"
DRIVER_OBJECT_STRUCT_NAME = "_DRIVER_OBJECT"
WDFDRIVER_STRUCT_NAME = "WDFDRIVER"
WDFDEVICE_INIT_STRUCT_NAME = "WDFDEVICE_INIT"
WDF_OBJECT_ATTRIBUTES_STRUCT_NAME = "_WDF_OBJECT_ATTRIBUTES"
WDF_OBJECT_CONTEXT_TYPE_INFO_STRUCT_NAME = "_WDF_OBJECT_CONTEXT_TYPE_INFO"
EVENT_FILTER_DESCRIPTOR_STRUCT_NAME = "_EVENT_FILTER_DESCRIPTOR"
WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME = "_WPP_TRACE_CONTROL_BLOCK"
DEVICE_OBJECT_STRUCT_NAME = "_DEVICE_OBJECT"
WDF_BIND_INFO_STRUCT_NAME = "_WDF_BIND_INFO"
WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME = "_WDF_PNPPOWER_EVENT_CALLBACKS"
WDF_FILEOBJECT_CONFIG_STRUCT_NAME = "_WDF_FILEOBJECT_CONFIG"
WDF_IO_QUEUE_CONFIG_STRUCT_NAME = "_WDF_IO_QUEUE_CONFIG"
WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME = "_WDF_QUERY_INTERFACE_CONFIG"


# We only accept KMDF 1.11 (no need currently to have another version)
kmdf1_11 = [
	("WdfChildListCreate",None),
	("WdfChildListGetDevice",None),
	("WdfChildListRetrievePdo",None),
	("WdfChildListRetrieveAddressDescription",None),
	("WdfChildListBeginScan",None),
	("WdfChildListEndScan",None),
	("WdfChildListBeginIteration",None),
	("WdfChildListRetrieveNextDevice",None),
	("WdfChildListEndIteration",None),
	("WdfChildListAddOrUpdateChildDescriptionAsPresent",None),
	("WdfChildListUpdateChildDescriptionAsMissing",None),
	("WdfChildListUpdateAllChildDescriptionsAsPresent",None),
	("WdfChildListRequestChildEject",None),
	("WdfCollectionCreate","typedef NTSTATUS __fastcall WDF_COLLECTION_CREATE(int, _WDF_OBJECT_ATTRIBUTES *CollectionAttributes, WDFCOLLECTION *Collection);"),
	("WdfCollectionGetCount","typedef ULONG __fastcall WDF_COLLECTION_GET_COUNT(int, WDFCOLLECTION Collection);"),
	("WdfCollectionAdd","typedef NTSTATUS __fastcall WDF_COLLECTION_ADD(int, WDFCOLLECTION Collection, WDFOBJECT Object);"),
	("WdfCollectionRemove","typedef VOID __fastcall WDF_COLLECTION_REMOVE(int, WDFCOLLECTION Collection, WDFOBJECT Item);"),
	("WdfCollectionRemoveItem","typedef VOID __fastcall WDF_COLLECTION_REMOVE_ITEM(int, WDFCOLLECTION Collection, ULONG Index);"),
	("WdfCollectionGetItem","typedef WDFOBJECT __fastcall WDF_COLLECTION_GET_ITEM(int, WDFCOLLECTION Collection, ULONG Index);"),
	("WdfCollectionGetFirstItem","typedef WDFOBJECT __fastcall WDF_COLLECTION_GET_FIRST_ITEM(int, WDFCOLLECTION Collection);"),
	("WdfCollectionGetLastItem",None),
	("WdfCommonBufferCreate",None),
	("WdfCommonBufferGetAlignedVirtualAddress",None),
	("WdfCommonBufferGetAlignedLogicalAddress",None),
	("WdfCommonBufferGetLength",None),
	("WdfControlDeviceInitAllocate",None),
	("WdfControlDeviceInitSetShutdownNotification",None),
	("WdfControlFinishInitializing",None),
	("WdfDeviceGetDeviceState",None),
	("WdfDeviceSetDeviceState",None),
	("WdfWdmDeviceGetWdfDeviceHandle",None),
	("WdfDeviceWdmGetDeviceObject",None),
	("WdfDeviceWdmGetAttachedDevice",None),
	("WdfDeviceWdmGetPhysicalDevice",None),
	("WdfDeviceWdmDispatchPreprocessedIrp",None),
	("WdfDeviceAddDependentUsageDeviceObject",None),
	("WdfDeviceAddRemovalRelationsPhysicalDevice",None),
	("WdfDeviceRemoveRemovalRelationsPhysicalDevice",None),
	("WdfDeviceClearRemovalRelationsDevices",None),
	("WdfDeviceGetDriver",None),
	("WdfDeviceRetrieveDeviceName",None),
	("WdfDeviceAssignMofResourceName",None),
	("WdfDeviceGetIoTarget",None),
	("WdfDeviceGetDevicePnpState",None),
	("WdfDeviceGetDevicePowerState",None),
	("WdfDeviceGetDevicePowerPolicyState",None),
	("WdfDeviceAssignS0IdleSettings",None),
	("WdfDeviceAssignSxWakeSettings",None),
	("WdfDeviceOpenRegistryKey",None),
	("WdfDeviceSetSpecialFileSupport",None),
	("WdfDeviceSetCharacteristics",None),
	("WdfDeviceGetCharacteristics",None),
	("WdfDeviceGetAlignmentRequirement",None),
	("WdfDeviceSetAlignmentRequirement",None),
	("WdfDeviceInitFree",None),
	("WdfDeviceInitSetPnpPowerEventCallbacks",None),
	("WdfDeviceInitSetPowerPolicyEventCallbacks",None),
	("WdfDeviceInitSetPowerPolicyOwnership",None),
	("WdfDeviceInitRegisterPnpStateChangeCallback",None),
	("WdfDeviceInitRegisterPowerStateChangeCallback",None),
	("WdfDeviceInitRegisterPowerPolicyStateChangeCallback",None),
	("WdfDeviceInitSetIoType","typedef VOID __fastcall WDF_DEVICE_INIT_SET_IOTYPE(int, WDFDEVICE_INIT *DeviceInit, WDF_DEVICE_IO_TYPE IoType);"),
	("WdfDeviceInitSetExclusive",None),
	("WdfDeviceInitSetPowerNotPageable",None),
	("WdfDeviceInitSetPowerPageable",None),
	("WdfDeviceInitSetPowerInrush",None),
	("WdfDeviceInitSetDeviceType",None),
	("WdfDeviceInitAssignName",None),
	("WdfDeviceInitAssignSDDLString",None),
	("WdfDeviceInitSetDeviceClass",None),
	("WdfDeviceInitSetCharacteristics",None),
	("WdfDeviceInitSetFileObjectConfig",None),
	("WdfDeviceInitSetRequestAttributes",None),
	("WdfDeviceInitAssignWdmIrpPreprocessCallback",None),
	("WdfDeviceInitSetIoInCallerContextCallback",None),
	("WdfDeviceCreate",None),
	("WdfDeviceSetStaticStopRemove",None),
	("WdfDeviceCreateDeviceInterface",None),
	("WdfDeviceSetDeviceInterfaceState",None),
	("WdfDeviceRetrieveDeviceInterfaceString",None),
	("WdfDeviceCreateSymbolicLink",None),
	("WdfDeviceQueryProperty",None),
	("WdfDeviceAllocAndQueryProperty",None),
	("WdfDeviceSetPnpCapabilities",None),
	("WdfDeviceSetPowerCapabilities",None),
	("WdfDeviceSetBusInformationForChildren",None),
	("WdfDeviceIndicateWakeStatus",None),
	("WdfDeviceSetFailed",None),
	("WdfDeviceStopIdleNoTrack",None),
	("WdfDeviceResumeIdleNoTrack",None),
	("WdfDeviceGetFileObject",None),
	("WdfDeviceEnqueueRequest",None),
	("WdfDeviceGetDefaultQueue",None),
	("WdfDeviceConfigureRequestDispatching",None),
	("WdfDmaEnablerCreate",None),
	("WdfDmaEnablerGetMaximumLength",None),
	("WdfDmaEnablerGetMaximumScatterGatherElements",None),
	("WdfDmaEnablerSetMaximumScatterGatherElements",None),
	("WdfDmaTransactionCreate",None),
	("WdfDmaTransactionInitialize",None),
	("WdfDmaTransactionInitializeUsingRequest",None),
	("WdfDmaTransactionExecute",None),
	("WdfDmaTransactionRelease",None),
	("WdfDmaTransactionDmaCompleted",None),
	("WdfDmaTransactionDmaCompletedWithLength",None),
	("WdfDmaTransactionDmaCompletedFinal",None),
	("WdfDmaTransactionGetBytesTransferred",None),
	("WdfDmaTransactionSetMaximumLength",None),
	("WdfDmaTransactionGetRequest",None),
	("WdfDmaTransactionGetCurrentDmaTransferLength",None),
	("WdfDmaTransactionGetDevice",None),
	("WdfDpcCreate",None),
	("WdfDpcEnqueue",None),
	("WdfDpcCancel",None),
	("WdfDpcGetParentObject",None),
	("WdfDpcWdmGetDpc",None),
	("WdfDriverCreate",None),
	("WdfDriverGetRegistryPath",None),
	("WdfDriverWdmGetDriverObject",None),
	("WdfDriverOpenParametersRegistryKey",None),
	("WdfWdmDriverGetWdfDriverHandle",None),
	("WdfDriverRegisterTraceInfo",None),
	("WdfDriverRetrieveVersionString",None),
	("WdfDriverIsVersionAvailable",None),
	("WdfFdoInitWdmGetPhysicalDevice",None),
	("WdfFdoInitOpenRegistryKey",None),
	("WdfFdoInitQueryProperty",None),
	("WdfFdoInitAllocAndQueryProperty",None),
	("WdfFdoInitSetEventCallbacks",None),
	("WdfFdoInitSetFilter",None),
	("WdfFdoInitSetDefaultChildListConfig",None),
	("WdfFdoQueryForInterface",None),
	("WdfFdoGetDefaultChildList",None),
	("WdfFdoAddStaticChild",None),
	("WdfFdoLockStaticChildListForIteration",None),
	("WdfFdoRetrieveNextStaticChild",None),
	("WdfFdoUnlockStaticChildListFromIteration",None),
	("WdfFileObjectGetFileName",None),
	("WdfFileObjectGetFlags",None),
	("WdfFileObjectGetDevice",None),
	("WdfFileObjectWdmGetFileObject",None),
	("WdfInterruptCreate",None),
	("WdfInterruptQueueDpcForIsr",None),
	("WdfInterruptSynchronize",None),
	("WdfInterruptAcquireLock",None),
	("WdfInterruptReleaseLock",None),
	("WdfInterruptEnable",None),
	("WdfInterruptDisable",None),
	("WdfInterruptWdmGetInterrupt",None),
	("WdfInterruptGetInfo",None),
	("WdfInterruptSetPolicy",None),
	("WdfInterruptGetDevice",None),
	("WdfIoQueueCreate",None),
	("WdfIoQueueGetState",None),
	("WdfIoQueueStart",None),
	("WdfIoQueueStop",None),
	("WdfIoQueueStopSynchronously",None),
	("WdfIoQueueGetDevice",None),
	("WdfIoQueueRetrieveNextRequest",None),
	("WdfIoQueueRetrieveRequestByFileObject",None),
	("WdfIoQueueFindRequest",None),
	("WdfIoQueueRetrieveFoundRequest",None),
	("WdfIoQueueDrainSynchronously",None),
	("WdfIoQueueDrain",None),
	("WdfIoQueuePurgeSynchronously",None),
	("WdfIoQueuePurge",None),
	("WdfIoQueueReadyNotify",None),
	("WdfIoTargetCreate",None),
	("WdfIoTargetOpen",None),
	("WdfIoTargetCloseForQueryRemove",None),
	("WdfIoTargetClose",None),
	("WdfIoTargetStart",None),
	("WdfIoTargetStop",None),
	("WdfIoTargetGetState",None),
	("WdfIoTargetGetDevice",None),
	("WdfIoTargetQueryTargetProperty",None),
	("WdfIoTargetAllocAndQueryTargetProperty",None),
	("WdfIoTargetQueryForInterface",None),
	("WdfIoTargetWdmGetTargetDeviceObject",None),
	("WdfIoTargetWdmGetTargetPhysicalDevice",None),
	("WdfIoTargetWdmGetTargetFileObject",None),
	("WdfIoTargetWdmGetTargetFileHandle",None),
	("WdfIoTargetSendReadSynchronously",None),
	("WdfIoTargetFormatRequestForRead",None),
	("WdfIoTargetSendWriteSynchronously",None),
	("WdfIoTargetFormatRequestForWrite",None),
	("WdfIoTargetSendIoctlSynchronously",None),
	("WdfIoTargetFormatRequestForIoctl",None),
	("WdfIoTargetSendInternalIoctlSynchronously",None),
	("WdfIoTargetFormatRequestForInternalIoctl",None),
	("WdfIoTargetSendInternalIoctlOthersSynchronously",None),
	("WdfIoTargetFormatRequestForInternalIoctlOthers",None),
	("WdfMemoryCreate",None),
	("WdfMemoryCreatePreallocated",None),
	("WdfMemoryGetBuffer",None),
	("WdfMemoryAssignBuffer",None),
	("WdfMemoryCopyToBuffer",None),
	("WdfMemoryCopyFromBuffer",None),
	("WdfLookasideListCreate",None),
	("WdfMemoryCreateFromLookaside",None),
	("WdfDeviceMiniportCreate",None),
	("WdfDriverMiniportUnload",None),
	("WdfObjectGetTypedContextWorker",None),
	("WdfObjectAllocateContext",None),
	("WdfObjectContextGetObject",None),
	("WdfObjectReferenceActual",None),
	("WdfObjectDereferenceActual",None),
	("WdfObjectCreate",None),
	("WdfObjectDelete",None),
	("WdfObjectQuery",None),
	("WdfPdoInitAllocate",None),
	("WdfPdoInitSetEventCallbacks",None),
	("WdfPdoInitAssignDeviceID",None),
	("WdfPdoInitAssignInstanceID",None),
	("WdfPdoInitAddHardwareID",None),
	("WdfPdoInitAddCompatibleID",None),
	("WdfPdoInitAddDeviceText",None),
	("WdfPdoInitSetDefaultLocale",None),
	("WdfPdoInitAssignRawDevice",None),
	("WdfPdoMarkMissing",None),
	("WdfPdoRequestEject",None),
	("WdfPdoGetParent",None),
	("WdfPdoRetrieveIdentificationDescription",None),
	("WdfPdoRetrieveAddressDescription",None),
	("WdfPdoUpdateAddressDescription",None),
	("WdfPdoAddEjectionRelationsPhysicalDevice",None),
	("WdfPdoRemoveEjectionRelationsPhysicalDevice",None),
	("WdfPdoClearEjectionRelationsDevices",None),
	("WdfDeviceAddQueryInterface",None),
	("WdfRegistryOpenKey",None),
	("WdfRegistryCreateKey",None),
	("WdfRegistryClose",None),
	("WdfRegistryWdmGetHandle",None),
	("WdfRegistryRemoveKey",None),
	("WdfRegistryRemoveValue",None),
	("WdfRegistryQueryValue",None),
	("WdfRegistryQueryMemory",None),
	("WdfRegistryQueryMultiString",None),
	("WdfRegistryQueryUnicodeString",None),
	("WdfRegistryQueryString",None),
	("WdfRegistryQueryULong",None),
	("WdfRegistryAssignValue",None),
	("WdfRegistryAssignMemory",None),
	("WdfRegistryAssignMultiString",None),
	("WdfRegistryAssignUnicodeString",None),
	("WdfRegistryAssignString",None),
	("WdfRegistryAssignULong",None),
	("WdfRequestCreate",None),
	("WdfRequestCreateFromIrp",None),
	("WdfRequestReuse",None),
	("WdfRequestChangeTarget",None),
	("WdfRequestFormatRequestUsingCurrentType",None),
	("WdfRequestWdmFormatUsingStackLocation",None),
	("WdfRequestSend",None),
	("WdfRequestGetStatus",None),
	("WdfRequestMarkCancelable",None),
	("WdfRequestUnmarkCancelable",None),
	("WdfRequestIsCanceled",None),
	("WdfRequestCancelSentRequest",None),
	("WdfRequestIsFrom32BitProcess",None),
	("WdfRequestSetCompletionRoutine",None),
	("WdfRequestGetCompletionParams",None),
	("WdfRequestAllocateTimer",None),
	("WdfRequestComplete",None),
	("WdfRequestCompleteWithPriorityBoost",None),
	("WdfRequestCompleteWithInformation",None),
	("WdfRequestGetParameters",None),
	("WdfRequestRetrieveInputMemory",None),
	("WdfRequestRetrieveOutputMemory",None),
	("WdfRequestRetrieveInputBuffer",None),
	("WdfRequestRetrieveOutputBuffer",None),
	("WdfRequestRetrieveInputWdmMdl",None),
	("WdfRequestRetrieveOutputWdmMdl",None),
	("WdfRequestRetrieveUnsafeUserInputBuffer",None),
	("WdfRequestRetrieveUnsafeUserOutputBuffer",None),
	("WdfRequestSetInformation",None),
	("WdfRequestGetInformation",None),
	("WdfRequestGetFileObject",None),
	("WdfRequestProbeAndLockUserBufferForRead",None),
	("WdfRequestProbeAndLockUserBufferForWrite",None),
	("WdfRequestGetRequestorMode",None),
	("WdfRequestForwardToIoQueue",None),
	("WdfRequestGetIoQueue",None),
	("WdfRequestRequeue",None),
	("WdfRequestStopAcknowledge",None),
	("WdfRequestWdmGetIrp",None),
	("WdfIoResourceRequirementsListSetSlotNumber",None),
	("WdfIoResourceRequirementsListSetInterfaceType",None),
	("WdfIoResourceRequirementsListAppendIoResList",None),
	("WdfIoResourceRequirementsListInsertIoResList",None),
	("WdfIoResourceRequirementsListGetCount",None),
	("WdfIoResourceRequirementsListGetIoResList",None),
	("WdfIoResourceRequirementsListRemove",None),
	("WdfIoResourceRequirementsListRemoveByIoResList",None),
	("WdfIoResourceListCreate",None),
	("WdfIoResourceListAppendDescriptor",None),
	("WdfIoResourceListInsertDescriptor",None),
	("WdfIoResourceListUpdateDescriptor",None),
	("WdfIoResourceListGetCount",None),
	("WdfIoResourceListGetDescriptor",None),
	("WdfIoResourceListRemove",None),
	("WdfIoResourceListRemoveByDescriptor",None),
	("WdfCmResourceListAppendDescriptor",None),
	("WdfCmResourceListInsertDescriptor",None),
	("WdfCmResourceListGetCount",None),
	("WdfCmResourceListGetDescriptor",None),
	("WdfCmResourceListRemove",None),
	("WdfCmResourceListRemoveByDescriptor",None),
	("WdfStringCreate",None),
	("WdfStringGetUnicodeString",None),
	("WdfObjectAcquireLock",None),
	("WdfObjectReleaseLock",None),
	("WdfWaitLockCreate",None),
	("WdfWaitLockAcquire",None),
	("WdfWaitLockRelease",None),
	("WdfSpinLockCreate",None),
	("WdfSpinLockAcquire",None),
	("WdfSpinLockRelease",None),
	("WdfTimerCreate",None),
	("WdfTimerStart",None),
	("WdfTimerStop",None),
	("WdfTimerGetParentObject",None),
	("WdfUsbTargetDeviceCreate",None),
	("WdfUsbTargetDeviceRetrieveInformation",None),
	("WdfUsbTargetDeviceGetDeviceDescriptor",None),
	("WdfUsbTargetDeviceRetrieveConfigDescriptor",None),
	("WdfUsbTargetDeviceQueryString",None),
	("WdfUsbTargetDeviceAllocAndQueryString",None),
	("WdfUsbTargetDeviceFormatRequestForString",None),
	("WdfUsbTargetDeviceGetNumInterfaces",None),
	("WdfUsbTargetDeviceSelectConfig",None),
	("WdfUsbTargetDeviceWdmGetConfigurationHandle",None),
	("WdfUsbTargetDeviceRetrieveCurrentFrameNumber",None),
	("WdfUsbTargetDeviceSendControlTransferSynchronously",None),
	("WdfUsbTargetDeviceFormatRequestForControlTransfer",None),
	("WdfUsbTargetDeviceIsConnectedSynchronous",None),
	("WdfUsbTargetDeviceResetPortSynchronously",None),
	("WdfUsbTargetDeviceCyclePortSynchronously",None),
	("WdfUsbTargetDeviceFormatRequestForCyclePort",None),
	("WdfUsbTargetDeviceSendUrbSynchronously",None),
	("WdfUsbTargetDeviceFormatRequestForUrb",None),
	("WdfUsbTargetPipeGetInformation",None),
	("WdfUsbTargetPipeIsInEndpoint",None),
	("WdfUsbTargetPipeIsOutEndpoint",None),
	("WdfUsbTargetPipeGetType",None),
	("WdfUsbTargetPipeSetNoMaximumPacketSizeCheck",None),
	("WdfUsbTargetPipeWriteSynchronously",None),
	("WdfUsbTargetPipeFormatRequestForWrite",None),
	("WdfUsbTargetPipeReadSynchronously",None),
	("WdfUsbTargetPipeFormatRequestForRead",None),
	("WdfUsbTargetPipeConfigContinuousReader",None),
	("WdfUsbTargetPipeAbortSynchronously",None),
	("WdfUsbTargetPipeFormatRequestForAbort",None),
	("WdfUsbTargetPipeResetSynchronously",None),
	("WdfUsbTargetPipeFormatRequestForReset",None),
	("WdfUsbTargetPipeSendUrbSynchronously",None),
	("WdfUsbTargetPipeFormatRequestForUrb",None),
	("WdfUsbInterfaceGetInterfaceNumber",None),
	("WdfUsbInterfaceGetNumEndpoints",None),
	("WdfUsbInterfaceGetDescriptor",None),
	("WdfUsbInterfaceSelectSetting",None),
	("WdfUsbInterfaceGetEndpointInformation",None),
	("WdfUsbTargetDeviceGetInterface",None),
	("WdfUsbInterfaceGetConfiguredSettingIndex",None),
	("WdfUsbInterfaceGetNumConfiguredPipes",None),
	("WdfUsbInterfaceGetConfiguredPipe",None),
	("WdfUsbTargetPipeWdmGetPipeHandle",None),
	("WdfVerifierDbgBreakPoint",None),
	("WdfVerifierKeBugCheck",None),
	("WdfWmiProviderCreate",None),
	("WdfWmiProviderGetDevice",None),
	("WdfWmiProviderIsEnabled",None),
	("WdfWmiProviderGetTracingHandle",None),
	("WdfWmiInstanceCreate",None),
	("WdfWmiInstanceRegister",None),
	("WdfWmiInstanceDeregister",None),
	("WdfWmiInstanceGetDevice",None),
	("WdfWmiInstanceGetProvider",None),
	("WdfWmiInstanceFireEvent",None),
	("WdfWorkItemCreate",None),
	("WdfWorkItemEnqueue",None),
	("WdfWorkItemGetParentObject",None),
	("WdfWorkItemFlush",None),
	("WdfCommonBufferCreateWithConfig",None),
	("WdfDmaEnablerGetFragmentLength",None),
	("WdfDmaEnablerWdmGetDmaAdapter",None),
	("WdfUsbInterfaceGetNumSettings",None), # here ends version 1.1
	("WdfDeviceRemoveDependentUsageDeviceObject",None),
	("WdfDeviceGetSystemPowerAction",None),
	("WdfInterruptSetExtendedPolicy",None),
	("WdfIoQueueAssignForwardProgressPolicy",None),
	("WdfPdoInitAssignContainerID",None),
	("WdfPdoInitAllowForwardingRequestToParent",None),
	("WdfRequestMarkCancelableEx",None),
	("WdfRequestIsReserved",None),
	("WdfRequestForwardToParentDeviceIoQueue",None), # here ends version 1.5 and 1.7
	("WdfCxDeviceInitAllocate",None),
	("WdfCxDeviceInitAssignWdmIrpPreprocessCallback",None),
	("WdfCxDeviceInitSetIoInCallerContextCallback",None),
	("WdfCxDeviceInitSetRequestAttributes",None),
	("WdfCxDeviceInitSetFileObjectConfig",None),
	("WdfDeviceWdmDispatchIrp",None),
	("WdfDeviceWdmDispatchIrpToIoQueue",None),
	("WdfDeviceInitSetRemoveLockOptions",None),
	("WdfDeviceConfigureWdmIrpDispatchCallback",None),
	("WdfDmaEnablerConfigureSystemProfile",None),
	("WdfDmaTransactionInitializeUsingOffset",None),
	("WdfDmaTransactionGetTransferInfo",None),
	("WdfDmaTransactionSetChannelConfigurationCallback",None),
	("WdfDmaTransactionSetTransferCompleteCallback",None),
	("WdfDmaTransactionSetImmediateExecution",None),
	("WdfDmaTransactionAllocateResources",None),
	("WdfDmaTransactionSetDeviceAddressOffset",None),
	("WdfDmaTransactionFreeResources",None),
	("WdfDmaTransactionCancel",None),
	("WdfDmaTransactionWdmGetTransferContext",None),
	("WdfInterruptQueueWorkItemForIsr",None),
	("WdfInterruptTryToAcquireLock",None),
	("WdfIoQueueStopAndPurge",None),
	("WdfIoQueueStopAndPurgeSynchronously",None),
	("WdfIoTargetPurge",None),
	("WdfUsbTargetDeviceCreateWithParameters",None),
	("WdfUsbTargetDeviceQueryUsbCapability",None),
	("WdfUsbTargetDeviceCreateUrb",None),
	("WdfUsbTargetDeviceCreateIsochUrb",None),
	("WdfDeviceWdmAssignPowerFrameworkSettings",None),
	("WdfDmaTransactionStopSystemTransfer",None),
	("WdfCxVerifierKeBugCheck",None),
	("WdfInterruptReportActive",None),
	("WdfInterruptReportInactive",None),
	("WdfDeviceInitSetReleaseHardwareOrderOnFailure",None),
	("WdfGetTriageInfo",None), # here ends version 1.9
	("WdfDeviceInitSetIoTypeEx",None),
	("WdfDeviceQueryPropertyEx",None),
	("WdfDeviceAllocAndQueryPropertyEx",None),
	("WdfDeviceAssignProperty",None),
	("WdfFdoInitQueryPropertyEx",None),
	("WdfFdoInitAllocAndQueryPropertyEx",None) # here ends version 1.11
	]

# Address of the array containing the WDF functions
WdfFunctions_address = 0

def add_WDFFUNCTIONS_structure():
	global WdfFunctions_address
	
	action = "Find KmdfLibrary 1.11"
	
	# Search the KmdfLibrary
	# Encode the string to UTF-16LE
	search_string_bytes = "KmdfLibrary".encode('utf-16le')
	
	# Convert the byte string to a hex string for find_binary
	hex_pattern = "".join(f'{b:02X} ' for b in search_string_bytes)
	
	# Start searching from the beginning of the IDB.
	aKmdflibrary_address = ida_bytes.find_bytes(
		hex_pattern,
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if aKmdflibrary_address == idaapi.BADADDR:
		print(f"Failed: {action}: KmdfLibrary not found!")
		return
		
	ref_to_aKmdflibrary_address = idc.get_first_dref_to(aKmdflibrary_address)
	
	# The name of the library is referenced in this structure:
	#WdfBindInfo	DCD 0x20				; Size
	#				DCD aKmdflibrary		; Component ; "KmdfLibrary"
	#				DCD 1					; Version.Major
	#				DCD 0xB					; Version.Minor
	#				DCD 0					; Version.Build
	#				DCD 0x1B0				; FuncCount
	#				DCD WdfFunctions		; FuncTable
	#				DCD 0					; Module
	
	major = idc.get_wide_dword(ref_to_aKmdflibrary_address + 4)
	minor = idc.get_wide_dword(ref_to_aKmdflibrary_address + 8)
	if (major!=1 or minor !=11):
		print(f"Failed: {action}: version {major}.{minor} not supported by this plugin!")
		return
	print(f"Done  : {action}")
	
	rename_offset(ref_to_aKmdflibrary_address-4, '_WDF_BIND_INFO WdfBindInfo') # TODO define structure _WDF_BIND_INFO
	
	# check if the structure already exists
	tif = ida_typeinf.tinfo_t()
	if tif.get_named_type(None, WDFFUNCTIONS_STRUCT_NAME):
		ida_typeinf.del_named_type(None, WDFFUNCTIONS_STRUCT_NAME, ida_typeinf.NTF_TYPE)
	
	udt = ida_typeinf.udt_type_data_t()
	for func_name, typedef in kmdf1_11:
		if typedef != None:
			typeName = extract_function_name_from_proto(typedef)
			# Create function type
			if 0 == idc.set_local_type(-1,typedef, idc.PT_SIL):
				print(f"Failed: Error when adding local type '{typeName}'!")
				udm = udt.add_member(func_name, ida_typeinf.tinfo_t(ida_typeinf.BTF_INT))
				continue
			# Add structure member with the created type
			struct_tinfo = idaapi.tinfo_t()
			struct_tinfo.get_named_type(None, typeName)
			ptr_struct_tinfo = idaapi.tinfo_t()
			ptr_struct_tinfo.create_ptr(struct_tinfo)
			udm = udt.add_member(func_name, ptr_struct_tinfo)
		else:
			# Add structure member with a default type
			udm = udt.add_member(func_name, ida_typeinf.tinfo_t(ida_typeinf.BTF_INT))
	
	if tif.create_udt(udt):
		tif.set_named_type(None, WDFFUNCTIONS_STRUCT_NAME)
	
	# Get the address pointed by 'FuncTable'
	WdfFunctions_address = ida_bytes.get_32bit(ref_to_aKmdflibrary_address + 20)
	rename_offset(WdfFunctions_address, 'WdfFunctions')
	apply_structure_to_offset(WdfFunctions_address, WDFFUNCTIONS_STRUCT_NAME)

def find_wdf_function_address(function_name):
	"""
	Finds the offset of a structure member by name.
	"""
	struct_id = idc.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
	if struct_id == idc.BADADDR:
		print(f"Structure '{WDFFUNCTIONS_STRUCT_NAME}' not found.")
		return idc.BADADDR
	
	function_offset = idc.get_member_offset(struct_id, function_name)
	return WdfFunctions_address+function_offset

def find_function_address(size, patterns):
	for func_ea in idautils.Functions():
		f = ida_funcs.get_func(func_ea)
		# The `f.end_ea` is the address of the byte *after* the function's last byte.
		# Therefore, the size of the function is `f.end_ea - f.start_ea`.
		func_size = f.end_ea - f.start_ea
		if func_size == size:
			for pattern in patterns:
				# Search for the pattern within the function's start and end addresses
				ea = ida_bytes.find_bytes(
					pattern,
					f.start_ea,
					range_end=f.end_ea,
					flags=ida_bytes.BIN_SEARCH_FORWARD,
					radix=16
				)
				if ea == f.start_ea:
					return func_ea
	return idc.BADADDR

def create_structure(struc_name, members):
	# Check if the structure already exists
	struc_id = idc.get_struc_id(struc_name)
	if struc_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struc_id)
	
	# Create a new structure
	struc_id = idc.add_struc(-1, struc_name, 0) # -1 adds it at the end, 0 means not a union
	if struc_id == idc.BADADDR:
		print(f"Failed to create structure '{struc_name}'!")
		return
	
	# Add each member to the new structure
	for name, offset, flag, type_id, size in members:
		# The add_struc_member function requires the structure ID,
		# member name, offset, flags, and size.
		result = idc.add_struc_member(
			struc_id,		# Structure ID
			name,			# Member name
			offset,			# Member offset
			flag,			# Flags (e.g., idc.FF_DWORD for a 4-byte DCD)
			type_id,		# Type ID (use -1 for simple types like DWORD)
			size			# Size of the member
		)
	
	return struc_id

def add_structures():
	ida_typeinf.set_compiler_id(ida_typeinf.COMP_MS) # Visual C++
	unicode_string_id = create_structure(
		UNICODE_STRING_STRUCT_NAME, 
		[
			("Length", 0x00, idc.FF_WORD, -1, 2),
			("MaximumLength", 0x02, idc.FF_WORD, -1, 2),
			("Buffer", 0x04, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		DRIVER_OBJECT_STRUCT_NAME,
		[
			("Type", 0x00, idc.FF_WORD, -1, 2),
			("Size", 0x02, idc.FF_WORD, -1, 2),
			("DeviceObject", 0x04, idc.FF_DWORD, -1, 4),
			("Flags", 0x08, idc.FF_DWORD, -1, 4),
			("DriverStart", 0x0C, idc.FF_DWORD, -1, 4),
			("DriverSize", 0x10, idc.FF_DWORD, -1, 4),
			("DriverSection", 0x14, idc.FF_DWORD, -1, 4),
			("DriverExtension", 0x18, idc.FF_DWORD, -1, 4),
			("DriverName", 0x1C, idc.FF_STRUCT, unicode_string_id, idc.get_struc_size(unicode_string_id)),
			("HardwareDatabase", 0x24, idc.FF_DWORD, -1, 4),
			("FastIoDispatch", 0x28, idc.FF_DWORD, -1, 4),
			("DriverInit", 0x2C, idc.FF_DWORD, -1, 4),
			("DriverStartIo", 0x30, idc.FF_DWORD, -1, 4),
			("DriverUnload", 0x34, idc.FF_DWORD, -1, 4),
			("MajorFunction", 0x38, idc.FF_DWORD | idc.FF_DATA, -1, 28*4), # The flag FF_DWORD|FF_DATA is used for a DCD type
		]
	)
	create_structure(
		WDF_DRIVER_CONFIG_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("EvtDriverDeviceAdd", 0x04, idc.FF_DWORD, -1, 4),
			("EvtDriverUnload", 0x08, idc.FF_DWORD, -1, 4),
			("DriverInitFlags", 0x0C, idc.FF_DWORD, -1, 4),
			("DriverPoolTag", 0x10, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDFDRIVER_STRUCT_NAME,
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDFDEVICE_INIT_STRUCT_NAME,
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'WDFDEVICE',
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'WDFCMRESLIST',
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'WDFREQUEST',
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'WDFFILEOBJECT',
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'WDFQUEUE',
		[
			("unused", 0x00, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDF_OBJECT_ATTRIBUTES_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("EvtCleanupCallback", 0x04, idc.FF_DWORD, -1, 4),
			("EvtDestroyCallback", 0x08, idc.FF_DWORD, -1, 4),
			("ExecutionLevel", 0x0C, idc.FF_DWORD, -1, 4),
			("SynchronizationScope", 0x10, idc.FF_DWORD, -1, 4),
			("ParentObject", 0x14, idc.FF_DWORD, -1, 4),
			("ContextSizeOverride", 0x18, idc.FF_DWORD, -1, 4),
			("ContextTypeInfo", 0x1C, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDF_OBJECT_CONTEXT_TYPE_INFO_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("ContextName", 0x04, idc.FF_DWORD, -1, 4),
			("ContextSize", 0x08, idc.FF_DWORD, -1, 4),
			("UniqueType", 0x0C, idc.FF_DWORD, -1, 4),
			("EvtDriverGetUniqueContextType", 0x10, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		EVENT_FILTER_DESCRIPTOR_STRUCT_NAME,
		[
			("Ptr", 0x00, idc.FF_QWORD, -1, 8),
			("Size", 0x08, idc.FF_DWORD, -1, 4),
			("Type", 0x0C, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME,
		[
			("Callback", 0x00, idc.FF_DWORD, -1, 4),
			("ControlGuid", 0x04, idc.FF_DWORD, -1, 4),
			("Next", 0x08, idc.FF_DWORD, -1, 4),
			("field_C", 0x0C, idc.FF_BYTE | idc.FF_DATA, -1, 4), # Adding a placeholder member for the undefined bytes.
			("Logger", 0x10, idc.FF_QWORD, -1, 8),
			("RegistryPath", 0x18, idc.FF_DWORD, -1, 4),
			("FlagsLen", 0x1C, idc.FF_BYTE, -1, 1),
			("Level", 0x1D, idc.FF_BYTE, -1, 1),
			("Reserved", 0x1E, idc.FF_WORD, -1, 2),
			("Flags", 0x20, idc.FF_DWORD, -1, 4),
			("ReservedFlags", 0x24, idc.FF_DWORD, -1, 4),
			("RegHandle", 0x28, idc.FF_QWORD, -1, 8),
		]
	)
	create_structure(
		DEVICE_OBJECT_STRUCT_NAME,
		[
			("dummy", 0x00, idc.FF_BYTE | idc.FF_DATA, -1, 0xB8), # Placeholder, no need to have the detail of this structure for the moment.
		]
	)
	create_structure(
		WDF_BIND_INFO_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("Component", 0x04, idc.FF_DWORD, -1, 4),
			("Version.Major", 0x08, idc.FF_DWORD, -1, 4),
			("Version.Minor", 0x0C, idc.FF_DWORD, -1, 4),
			("Version.Build", 0x10, idc.FF_DWORD, -1, 4),
			("FuncCount", 0x14, idc.FF_DWORD, -1, 4),
			("FuncTable", 0x18, idc.FF_DWORD, -1, 4),
			("Module", 0x1C, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		'_EVENT_DESCRIPTOR',
		[
			("Id", 0x00, idc.FF_WORD, -1, 2),
			("Version", 0x02, idc.FF_BYTE, -1, 1),
			("Channel", 0x03, idc.FF_BYTE, -1, 1),
			("Level", 0x04, idc.FF_BYTE, -1, 1),
			("Opcode", 0x05, idc.FF_BYTE, -1, 1),
			("Task", 0x06, idc.FF_WORD, -1, 2),
			("Keyword", 0x08, idc.FF_QWORD, -1, 8),
		]
	)
	create_structure(
		WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("EvtDeviceD0Entry", 0x04, idc.FF_DWORD, -1, 4),
			("EvtDeviceD0EntryPostInterruptsEnabled", 0x08, idc.FF_DWORD, -1, 4),
			("EvtDeviceD0Exit", 0x0C, idc.FF_DWORD, -1, 4),
			("EvtDeviceD0ExitPreInterruptsDisabled", 0x10, idc.FF_DWORD, -1, 4),
			("EvtDevicePrepareHardware", 0x14, idc.FF_DWORD, -1, 4),
			("EvtDeviceReleaseHardware", 0x18, idc.FF_DWORD, -1, 4),
			("EvtDeviceSelfManagedIoCleanup", 0x1C, idc.FF_DWORD, -1, 4),
			("EvtDeviceSelfManagedIoFlush", 0x20, idc.FF_DWORD, -1, 4),
			("EvtDeviceSelfManagedIoInit", 0x24, idc.FF_DWORD, -1, 4),
			("EvtDeviceSelfManagedIoSuspend", 0x28, idc.FF_DWORD, -1, 4),
			("EvtDeviceSelfManagedIoRestart", 0x2C, idc.FF_DWORD, -1, 4),
			("EvtDeviceSurpriseRemoval", 0x30, idc.FF_DWORD, -1, 4),
			("EvtDeviceQueryRemove", 0x34, idc.FF_DWORD, -1, 4),
			("EvtDeviceQueryStop", 0x38, idc.FF_DWORD, -1, 4),
			("EvtDeviceUsageNotification", 0x3C, idc.FF_DWORD, -1, 4),
			("EvtDeviceRelationsQuery", 0x40,idc.FF_DWORD, -1, 4),
			("EvtDeviceUsageNotificationEx", 0x44, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDF_FILEOBJECT_CONFIG_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("EvtDeviceFileCreate", 0x04, idc.FF_DWORD, -1, 4),
			("EvtFileClose", 0x08, idc.FF_DWORD, -1, 4),
			("EvtFileCleanup", 0x0C, idc.FF_DWORD, -1, 4),
			("AutoForwardCleanupClose", 0x10, idc.FF_DWORD, -1, 4),
			("FileObjectClass", 0x14, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDF_IO_QUEUE_CONFIG_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("DispatchType", 0x04, idc.FF_DWORD, -1, 4),
			("PowerManaged", 0x08, idc.FF_DWORD, -1, 4),
			("AllowZeroLengthRequests", 0x0C, idc.FF_BYTE, -1, 1),
			("DefaultQueue", 0x0D, idc.FF_BYTE, -1, 1),
			("EvtIoDefault", 0x10, idc.FF_DWORD, -1, 4),
			("EvtIoRead", 0x14, idc.FF_DWORD, -1, 4),
			("EvtIoWrite", 0x18, idc.FF_DWORD, -1, 4),
			("EvtIoDeviceControl", 0x1C, idc.FF_DWORD, -1, 4),
			("EvtIoInternalDeviceControl", 0x20, idc.FF_DWORD, -1, 4),
			("EvtIoStop", 0x24, idc.FF_DWORD, -1, 4),
			("EvtIoResume", 0x28, idc.FF_DWORD, -1, 4),
			("EvtIoCanceledOnQueue", 0x2C, idc.FF_DWORD, -1, 4),
			("Settings", 0x30, idc.FF_DWORD, -1, 4),
			("Driver", 0x34, idc.FF_DWORD, -1, 4),
		]
	)
	create_structure(
		WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME,
		[
			("Size", 0x00, idc.FF_DWORD, -1, 4),
			("Interface", 0x04, idc.FF_DWORD, -1, 4),
			("InterfaceType", 0x08, idc.FF_DWORD, -1, 4),
			("SendQueryToParentStack", 0x0C, idc.FF_BYTE, -1, 1),
			("EvtDeviceProcessQueryInterfaceRequest", 0x10, idc.FF_DWORD, -1, 4),
			("ImportInterface", 0x14, idc.FF_BYTE, -1, 1),
			("align", 0x15, idc.FF_BYTE, -1, 3),
		]
	)
	if idc.set_local_type(-1,"typedef unsigned __int16 wchar_t;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'wchar_t'!")
	if idc.set_local_type(-1,"typedef unsigned int size_t;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'size_t'!")
	if idc.set_local_type(-1,"typedef int NTSTATUS;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'NTSTATUS'!")
	if idc.set_local_type(-1,"typedef void *WDFOBJECT;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'WDFOBJECT'!")
	if idc.set_local_type(-1,"typedef unsigned int ULONG;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'ULONG'!")
	if idc.set_local_type(-1,"typedef void VOID;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'VOID'!")
	if idc.set_local_type(-1,"typedef void *WDFCOLLECTION;", idc.PT_SIL) == 0:
		print("Failed: Error when adding local type 'WDFCOLLECTION'!")
	add_WDFFUNCTIONS_structure()


def add_NT_STATUS_VALUES_enum():
	script_path = os.path.abspath(__file__)
	# Get the directory containing the script
	current_folder_path = os.path.dirname(script_path)
	file_path = os.path.join(current_folder_path, "ntstatus.h")
	with open(file_path, 'r') as file:
		file_content = file.read()
	tif = ida_typeinf.tinfo_t(file_content) # Much faster and memory efficient than using idc.add_enum_member for each member
	tif.set_named_type(None, "NT_STATUS_VALUES")


def add_enums():
	enum_id = idc.add_enum(-1, '_WPP_TRACE_API_SUITE', 0x00000010)
	members_to_add = {
		"WppTraceDisabledSuite": 0,
		"WppTraceWin2K": 1,
		"WppTraceWinXP": 2,
		"WppTraceTraceLH": 3,
		"WppTraceServer08": 4,
		"WppTraceMaxSuite": 5
	}
	for member_name, member_value in members_to_add.items():
		idc.add_enum_member(enum_id, member_name, member_value, -1)
	
	enum_id = idc.add_enum(-1, '_TRACE_INFORMATION_CLASS', 0x00000010)
	members_to_add = {
		"TraceIdClass": 0,
		"TraceHandleClass": 1,
		"TraceEnableFlagsClass": 2,
		"TraceEnableLevelClass": 3,
		"GlobalLoggerHandleClass": 4,
		"EventLoggerHandleClass": 5,
		"AllLoggerHandlesClass": 6,
		"TraceHandleByNameClass": 7,
		"LoggerEventsLostClass": 8,
		"TraceSessionSettingsClass": 9,
		"LoggerEventsLoggedClass": 0xA,
		"DiskIoNotifyRoutinesClass": 0xB,
		"TraceInformationClassReserved1": 0xC,
		"FltIoNotifyRoutinesClass": 0xD,
		"TraceInformationClassReserved2": 0xE,
		"WdfNotifyRoutinesClass": 0xF,
		"MaxTraceInformationClass": 0x10
	}
	for member_name, member_value in members_to_add.items():
		idc.add_enum_member(enum_id, member_name, member_value, -1)	
	
	enum_id = idc.add_enum(-1, 'WDF_DEVICE_IO_TYPE', 0x00000010)
	members_to_add = {
		"WdfDeviceIoUndefined": 0,
		"WdfDeviceIoNeither": 1,
		"WdfDeviceIoBuffered": 2,
		"WdfDeviceIoDirect": 3,
		"WdfDeviceIoBufferedOrDirect": 4,
		"WdfDeviceIoMaximum": 5
	}
	for member_name, member_value in members_to_add.items():
		idc.add_enum_member(enum_id, member_name, member_value, -1)
	
	add_NT_STATUS_VALUES_enum()

def extract_function_name_from_proto(proto):
	# Split the string by opening parenthesis
	parts = proto.split('(')
	function_name_with_spaces = parts[0]
	# Split the string by space and keep the last element
	function_name = function_name_with_spaces.split(' ')[-1]
	return function_name

def is_renamed_function(function_address):
	function_name = idc.get_name(function_address)
	original_name = f"sub_{function_address:X}"
	return function_name != original_name

def is_renamed_offset(offset_address):
	offset_name = idc.get_name(offset_address)
	original_name = f"off_{offset_address:X}"
	return offset_name != original_name

def rename_function(function_address, new_proto, force=False):
	old_name = idc.get_name(function_address)
	action = f"Rename function '{old_name}' to '{new_proto}'"
	if not force and is_renamed_function(function_address):
		print(f"Failed: {action}: Function is already renamed.")
		return
	
	wanted_new_function_name = extract_function_name_from_proto(new_proto)
	update_type = wanted_new_function_name != new_proto
	
	retry = 0
	new_function_name = wanted_new_function_name
	while old_name!=new_function_name and idc.get_name_ea_simple(new_function_name)!=idc.BADADDR and retry < 5:
		new_function_name += '_'
		retry += 1
	
	if retry < 5:
		idc.set_name(function_address, new_function_name)
		if new_function_name != wanted_new_function_name:
			action += f" renamed to {new_function_name} to avoid collision"
		if update_type:
			result = idc.SetType(function_address, new_proto)
			if not result:
				action +=" but failed to apply proto"
		print(f"Done  : {action}")
	else:
		print(f"Failed: {action}: Failed to rename to '{wanted_new_function_name}' after {retry} retries!")

def get_structure_member_name(structure_name, member_offset):
	sid = idc.get_struc_id(structure_name)
	member_name = idc.get_member_name(sid, member_offset)
	return member_name

# Iterate through a C-tree to find all the calls to a WDF function or a simple function
# when possible returns also the assignement parent of the call to the function.
# The memory address of the WDF function is casted in order to be called
# example: ((int (__fastcall *)(int, int, int, int *, _WDF_DRIVER_CONFIG *, _DWORD))WdfFunctions.WdfDriverCreate)(...)
# List of cot_... values : https://gist.github.com/icecr4ck/9dea9d1de052f0b2b417abf0046cc0f6#type-of-expressions-and-statements
class find_all_call_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_function_name):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS) # maintain parent information
		self.list_found_call = [] # tuples (call_expr, asg_citem)
		self.search_function_name = search_function_name

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_call:
			if expr.x.op  == idaapi.cot_cast: # Case of a call to a WDF function
				if expr.x.x.op == idaapi.cot_memref:
					if expr.x.x.x.op == idaapi.cot_obj:
						member_offset = expr.x.x.m
						if str(expr.x.x.x.type) == 'WDFFUNCTIONS':
							member_name = get_structure_member_name(WDFFUNCTIONS_STRUCT_NAME, member_offset)
							if member_name == self.search_function_name:
								call_expr = expr
								asg_citem = None
								parents_len = len(self.parents)
								if parents_len > 1 and self.parents[parents_len-1].op == idaapi.cot_asg:
									asg_citem = self.parents[parents_len-1]
								elif parents_len > 2 and self.parents[parents_len-2].op == idaapi.cot_asg:
									asg_citem = self.parents[parents_len-2]
								self.list_found_call.append((call_expr, asg_citem))
				elif expr.x.x.op == idaapi.cot_memptr:
					if expr.x.x.x.op == idaapi.cot_obj:
						member_offset = expr.x.x.m
						if str(expr.x.x.x.type) == 'WDFFUNCTIONS *':
							member_name = get_structure_member_name(WDFFUNCTIONS_STRUCT_NAME, member_offset)
							if member_name == self.search_function_name:
								call_expr = expr
								asg_citem = None
								parents_len = len(self.parents)
								if parents_len > 1 and self.parents[parents_len-1].op == idaapi.cot_asg:
									asg_citem = self.parents[parents_len-1]
								elif parents_len > 2 and self.parents[parents_len-2].op == idaapi.cot_asg:
									asg_citem = self.parents[parents_len-2]
								self.list_found_call.append((call_expr, asg_citem))
			elif expr.x.op  == idaapi.cot_obj: # Case of a call to an imported function or to another function of the driver
				object_name = idc.get_name(expr.x.obj_ea)
				if object_name == self.search_function_name:
					call_expr = expr
					asg_citem = None
					parents_len = len(self.parents)
					if parents_len > 1 and self.parents[parents_len-1].op == idaapi.cot_asg:
						asg_citem = self.parents[parents_len-1]
					elif parents_len > 2 and self.parents[parents_len-2].op == idaapi.cot_asg:
						asg_citem = self.parents[parents_len-2]
					self.list_found_call.append((call_expr, asg_citem))
		return 0  # Continue traversal

# Iterate through a C-tree to find the assignment of a variable of a given type
class find_asg_type_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_var_type, search_var_type_member):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST) # do not maintain parent information
		self.found_asg = None
		self.search_var_type = search_var_type
		self.search_var_type_member = search_var_type_member

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			if expr.x.op  == idaapi.cot_memref:
				if expr.x.x.op == idaapi.cot_var:
					if str(expr.x.x.v.getv().tif) == self.search_var_type:
						member_offset = expr.x.m
						member_name = get_structure_member_name(self.search_var_type, member_offset)
						if member_name == self.search_var_type_member:
							self.found_asg = expr
							return 1  # Stop traversal
				elif expr.x.x.op == idaapi.cot_obj:
					if str(expr.x.x.type) == self.search_var_type:
						member_offset = expr.x.m
						member_name = get_structure_member_name(self.search_var_type, member_offset)
						if member_name == self.search_var_type_member:
							self.found_asg = expr
							return 1  # Stop traversal
		return 0  # Continue traversal

# Iterate through a C-tree to find all the assignments of a variable of a given name
class find_all_asg_name_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_var_name):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST) # do not maintain parent information
		self.list_found_asg = []
		self.search_var_name = search_var_name

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			if expr.x.op  == idaapi.cot_var:
				if expr.x.v.getv().name == self.search_var_name:
					self.list_found_asg.append(expr)
		return 0  # Continue traversal

# Iterate through a C-tree to find all the assignments of any memory object
class find_all_obj_asg_visitor(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST) # do not maintain parent information
		self.list_found_asg = []

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			if expr.x.op  == idaapi.cot_obj:
				self.list_found_asg.append(expr)
		return 0  # Continue traversal

def apply_structure_to_stack_parameter(called_name, function_address, call_expr, idx_param, struct_name, new_var_name):
	function_name = idc.get_func_name(function_address)
	
	action = f"Apply structure {struct_name} in the stack frame of the function '{function_name}'"
	
	if call_expr.a.size() < idx_param+1: # +1 because 0-based index
		print(f"Failed: {action}: The function '{called_name}' does not have a {idx_param+1}th parameter.")
		return
	param_expr = call_expr.a[idx_param]
	if param_expr.op == idaapi.cot_ref: # &variable
		param_expr = param_expr.x
	if (param_expr.op != idaapi.cot_var) or (not param_expr.v.getv().is_stk_var()):
		print(f"In {function_name}, the {idx_param+1}th parameter of the function '{called_name}' is not a stack frame variable.")
		return
	struc_id = idc.get_struc_id(struct_name)
	tid = ida_typeinf.get_named_type_tid(struct_name)
	struc_size = idc.get_struc_size(tid)
	frame_id = idc.get_frame_id(function_address)
	stack_frame_offset = param_expr.v.getv().get_stkoff()
	action += f" at the offset {hex(stack_frame_offset)}"
	#Delete existing members of the stack frame
	for i in range(struc_size-1):
		idc.del_struc_member(frame_id, stack_frame_offset + i)
	result = idc.add_struc_member(frame_id, new_var_name, stack_frame_offset, idc.FF_STRUCT|idc.FF_DATA, struc_id, struc_size)
	if result != 0:
		print(f"Failed: {action}: Error code {result}!")
		return
	print(f"Done  : {action}")

def rename_offset(offset_address, new_definition):
	old_name = idc.get_name(offset_address)
	action = f"Rename memory offset '{old_name}' to '{new_definition}'"
	matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', new_definition)
	if matches:
		wanted_new_name = matches[-1] # get the last match of the capturing group
	else:
		print(f"Failed: {action}: No name found in '{new_definition}'!")
		return
	
	retry = 0
	new_name = wanted_new_name
	while old_name!=new_name and idc.get_name_ea_simple(new_name)!=idc.BADADDR and retry < 5:
		new_name += '_'
		retry += 1
	
	if retry < 5:
		idc.set_name(offset_address, new_name)
		if new_name != wanted_new_name:
			action += f", renamed to {new_name} to avoid collision"
		if wanted_new_name != new_definition: # there's some type definition in addition to the name.
			new_type = new_definition.replace(wanted_new_name,'') # remove the name to have a correct type.
			result = idc.SetType(offset_address, new_type)
			if not result:
				action += " but failed to apply type"
		print(f"Done  : {action}")
	else:
		print(f"Failed: {action}: Failed to rename to '{wanted_new_name}' after {retry} retries!")


def apply_structure_to_offset(offset_address, struct_name):
	action = f"Apply structure {struct_name} at the memory offset {hex(offset_address)}"
	struc_id = idc.get_struc_id(struct_name)
	tid = ida_typeinf.get_named_type_tid(struct_name)
	struc_size = idc.get_struc_size(tid)
	#Delete existing items
	for i in range(struc_size-1):
		ida_bytes.del_items(offset_address + i, ida_bytes.get_item_size(offset_address + i))
	# Apply the structure to the memory address
	result = ida_bytes.create_struct(offset_address, struc_size, struc_id, True) #Force=True
	if result != True:
		print(f"Failed: {action}")
		return
	print(f"Done  : {action}")

def rename_wdf_context_type_info(ContextTypeInfo_address):
	ContextTypeInfo_structure_address = ida_bytes.get_32bit(ContextTypeInfo_address)
	apply_structure_to_offset(ContextTypeInfo_structure_address, WDF_OBJECT_CONTEXT_TYPE_INFO_STRUCT_NAME)
	context_name_address = ida_bytes.get_32bit(ContextTypeInfo_structure_address+4) #Read the value of the pointer to the name of the context
	context_size = ida_bytes.get_32bit(ContextTypeInfo_structure_address+8)
	context_name = idc.get_strlit_contents(context_name_address).decode('utf-8')
	ContextTypeInfo_structure_name = "WDF_"+context_name+"_TYPE_INFO"
	rename_offset(ContextTypeInfo_structure_address, "_WDF_OBJECT_CONTEXT_TYPE_INFO "+ContextTypeInfo_structure_name)
	
	action = f"Create structure {context_name}."
	# Create the structure of the context
	# Check if the structure already exists
	struc_id = idc.get_struc_id(context_name)
	if struc_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struc_id)
	# Create a new structure
	struc_id = idc.add_struc(-1, context_name, 0) # -1 adds it at the end, 0 means not a union
	if struc_id == idc.BADADDR:
		print(f"Failed: {action}")
		return None
	for idx in range(context_size):
		idc.add_struc_member(struc_id, f"field_{idx:x}", idx, idc.FF_BYTE | idc.FF_DATA, -1,1)
	print(f"Done  : {action}")
	return context_name

def get_imported_function_address(func_name):
	for name_ea, name in idautils.Names():
		if name == func_name:
			return name_ea
	return idc.BADADDR

def rename_function_McGenEventRegister():
	EtwRegister_address = get_imported_function_address('EtwRegister')
	if EtwRegister_address == idc.BADADDR:
		print("EtwRegister is not imported !")
		return
	rename_function(EtwRegister_address, 'int __fastcall EtwRegister(const _GUID *ProviderId, void (__fastcall *EnableCallback)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *CallbackContext), void *CallbackContext, unsigned __int64 *RegHandle)', force=True)
	# List comprehension to collect only code xrefs (because we can have multiple Xrefs for the same call)
	code_xrefs = [
		xref for xref in idautils.XrefsTo(EtwRegister_address)
		if xref.type in [
			ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
		]
	]
	if len(code_xrefs) < 1:
		print("EtwRegister is never called !")
		return
	if len(code_xrefs) > 1:
		print("EtwRegister is called more than once !")
		return
	xref = code_xrefs[0]
	# Get the function object containing the target address
	McGenEventRegister_function = ida_funcs.get_func(xref.frm)
	rename_function(McGenEventRegister_function.start_ea, 'int __fastcall McGenEventRegister(const _GUID *ProviderId, void (__fastcall *EnableCallback)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *), void *CallbackContext, unsigned __int64 *RegHandle)', force=True)
	# Decompile the function McGenEventRegister to find the call to EtwRegister
	cfunc = ida_hexrays.decompile(McGenEventRegister_function,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_all_call_visitor('EtwRegister')
	visitor.apply_to(cfunc.body, None)
	call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to EtwRegister
	if call_expr.a.size() < 2: 
		print("The function call does not have a 2nd parameter.")
		return
	param_expr = call_expr.a[1] # Because 0-based index
	if param_expr.op == idaapi.cot_cast and param_expr.x.op == idaapi.cot_obj:
		rename_function(param_expr.x.obj_ea, 'void __fastcall ETW_EnableCallback(const _GUID *SourceId, unsigned int ControlCode, unsigned __int8 Level, unsigned __int64 MatchAnyKeyword, unsigned __int64 MatchAllKeyword, _EVENT_FILTER_DESCRIPTOR *FilterData, void *CallbackContext)', force=True)
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(McGenEventRegister_function.start_ea, True)
	
	xrefs = idautils.XrefsTo(McGenEventRegister_function.start_ea)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	count = 0
	for xref in xrefs_list:
		# Get the function object containing the target address
		calling_function = ida_funcs.get_func(xref.frm)
		if calling_function == None:
			continue
		# Decompile the calling function to find the call to McGenEventRegister
		cfunc = ida_hexrays.decompile(calling_function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('McGenEventRegister')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to McGenEventRegister
		if call_expr.a.size() < 4: 
			print(f"In {idc.get_name(calling_function.start_ea)}, the call of 'McGenEventRegister' does not have 4 parameters.")
			continue
		count += 1
		ProviderId_param_expr = call_expr.a[0]
		if ProviderId_param_expr.op == idaapi.cot_ref and ProviderId_param_expr.x.op == idaapi.cot_obj:
			rename_offset(ProviderId_param_expr.x.obj_ea, f'_GUID ETW_Provider_GUID_{count:02}')
		CallbackContext_param_expr = call_expr.a[2]
		if CallbackContext_param_expr.op == idaapi.cot_ref and CallbackContext_param_expr.x.op == idaapi.cot_obj:
			rename_offset(CallbackContext_param_expr.x.obj_ea, f'void *ETW_CallbackContext_{count:02}')
		RegHandle_param_expr = call_expr.a[3]
		if RegHandle_param_expr.op == idaapi.cot_cast and RegHandle_param_expr.x.op == idaapi.cot_ref and RegHandle_param_expr.x.x.op == idaapi.cot_obj:
			rename_offset(RegHandle_param_expr.x.x.obj_ea, f'unsigned __int64 ETW_RegistrationHandle_{count:02}')

def rename_function_McGenEventUnregister():
	EtwUnregister_address = get_imported_function_address('EtwUnregister')
	if EtwUnregister_address == idc.BADADDR:
		print("EtwUnregister is not imported.")
		return
	rename_function(EtwUnregister_address, 'int __fastcall EtwUnregister(unsigned __int64 *RegHandle)', force=True)
	# List comprehension to collect only code xrefs (because we can have multiple Xrefs for the same call)
	code_xrefs = [
		xref for xref in idautils.XrefsTo(EtwUnregister_address)
		if xref.type in [
			ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
		]
	]
	if len(code_xrefs) < 1:
		print("EtwUnregister is never called !")
		return
	if len(code_xrefs) > 1:
		print("EtwUnregister is called more than once !")
		return
	xref = code_xrefs[0]
	# Get the function object containing the target address
	McGenEventUnregister_function = ida_funcs.get_func(xref.frm)
	rename_function(McGenEventUnregister_function.start_ea, 'int __fastcall McGenEventUnregister(unsigned __int64 *RegHandle)', force=True)

def rename_function_WppInitKm_and_WppCleanupKm():
	IoWMIRegistrationControl_address = get_imported_function_address('IoWMIRegistrationControl')
	if IoWMIRegistrationControl_address == idc.BADADDR:
		print("IoWMIRegistrationControl is not imported.")
		return
	xrefs = idautils.XrefsTo(IoWMIRegistrationControl_address)
	# List comprehension to collect only code xrefs (because we can have multiple Xrefs for the same call)
	code_xrefs = [
		xref for xref in idautils.XrefsTo(IoWMIRegistrationControl_address)
		if xref.type in [
			ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
		]
	]
	if len(code_xrefs) < 1:
		print("IoWMIRegistrationControl is never called !")
		return
	if len(code_xrefs) > 2:
		print("IoWMIRegistrationControl is called more than twice !")
		return
	for xref in code_xrefs:
		# Get the function object containing the target address
		calling_function = ida_funcs.get_func(xref.frm)
		# Decompile the calling function to find the call to IoWMIRegistrationControl
		cfunc = ida_hexrays.decompile(calling_function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('IoWMIRegistrationControl')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to IoWMIRegistrationControl
		if call_expr.a.size() < 2: 
			print("The function call does not have 2 parameters.")
			continue
		param1_expr = call_expr.a[0]
		param2_expr = call_expr.a[1]
		if param2_expr.op == idaapi.cot_num and param2_expr.numval() & 1 == 1 : # WMIREG_ACTION_REGISTER
			if param1_expr.op == idaapi.cot_ref and param1_expr.x.op == idaapi.cot_obj:
				apply_structure_to_offset(param1_expr.x.obj_ea, WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME) # In reality, it's an union named "WPP_PROJECT_CONTROL_BLOCK" witch contains the structure "_WPP_TRACE_CONTROL_BLOCK"
				rename_offset(param1_expr.x.obj_ea, f'_WPP_TRACE_CONTROL_BLOCK WPP_MAIN_CB')
				rename_function(calling_function.start_ea, 'void __fastcall WppInitKm(_DEVICE_OBJECT *DevObject, const _UNICODE_STRING *RegPath)', force=True)
				WPP_GLOBAL_Control_address = idc.get_operand_value(calling_function.start_ea+8, 1) # second operand (operand 1)
				rename_offset(WPP_GLOBAL_Control_address, '_WPP_TRACE_CONTROL_BLOCK *WPP_GLOBAL_Control') # In reality, it's an union named "WPP_PROJECT_CONTROL_BLOCK" witch contains the structure "_WPP_TRACE_CONTROL_BLOCK"
		elif param2_expr.op == idaapi.cot_num and param2_expr.numval() & 2 == 2 : # WMIREG_ACTION_DEREGISTER
			rename_function(calling_function.start_ea, 'void __fastcall WppCleanupKm(_DEVICE_OBJECT *DeviceObject)', force=True)
	# Clear the decompilation caches to force the usage of the type _WPP_TRACE_CONTROL_BLOCK
	ida_hexrays.clear_cached_cfuncs()

def rename_offset_WPP_CONTROL_GUID():
	WPP_MAIN_CB_address = idc.get_name_ea_simple('WPP_MAIN_CB')
	if WPP_MAIN_CB_address != idc.BADADDR:
		xrefs = idautils.XrefsTo(WPP_MAIN_CB_address+4) #_WPP_TRACE_CONTROL_BLOCK.ControlGuid
		xrefs_list = list(xrefs)
		for xref in xrefs_list:
			# Get the function object containing the target address
			calling_function = ida_funcs.get_func(xref.frm)
			if calling_function == None:
				continue
			# Decompile the calling function to find an assignment
			cfunc = ida_hexrays.decompile(calling_function,None,ida_hexrays.DECOMP_NO_WAIT)
			visitor = find_asg_type_visitor(WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME, 'ControlGuid')
			visitor.apply_to(cfunc.body, None)
			asg_expr = visitor.found_asg
			if asg_expr:
				if asg_expr.y.op == idaapi.cot_cast: # there is a cast from _UNKNOWN* to int
					if asg_expr.y.x.op == idaapi.cot_ref and asg_expr.y.x.x.op == idaapi.cot_obj:
						rename_offset(asg_expr.y.x.x.obj_ea, 'GUID WPP_CONTROL_GUID')

def rename_function_WppLoadTracingSupport():
	# Search the string "EtwRegisterClassicProvider"
	# Encode the string to UTF-16LE
	search_string_bytes = "EtwRegisterClassicProvider".encode('utf-16le')
	
	# Convert the byte string to a hex string for find_binary
	hex_pattern = "".join(f'{b:02X} ' for b in search_string_bytes)
	
	# Start searching from the beginning of the IDB.
	aEtwRegisterClassicProvider_address = ida_bytes.find_bytes(
		hex_pattern,
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)	
	if aEtwRegisterClassicProvider_address == idaapi.BADADDR:
		return
	
	ref_to_aEtwRegisterClassicProvider_address = idc.get_first_dref_to(aEtwRegisterClassicProvider_address)
	
	# Get the function object containing the target address
	function = ida_funcs.get_func(ref_to_aEtwRegisterClassicProvider_address)
	
	rename_function(function.start_ea,'int __fastcall WppLoadTracingSupport()', force=True)
	
	# Decompile the function to find memory assignments
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	
	memory_assignment_data = [
		(0, 'unsigned __int8 (__fastcall *)(unsigned int *, unsigned int *, unsigned int *, _UNICODE_STRING *) pfnWppGetVersion', 'first'),
		(1, 'int (__fastcall *)(unsigned __int64 LoggerHandle, unsigned int MessageFlags, const _GUID *MessageGuid, unsigned __int16 MessageNumber, ...) pfnWppTraceMessage', 'second'),
		(2, 'int (__fastcall *)(_TRACE_INFORMATION_CLASS, void *, unsigned int, unsigned int *, void *) pfnWppQueryTraceInformation', 'third'),
		(3, '_WPP_TRACE_API_SUITE WPPTraceSuite', 'fourth'),
		(4, 'int (__fastcall *)(const _GUID *, unsigned int, void (__fastcall *)(const _GUID *, unsigned __int8, void *, void *), void *, unsigned __int64 *) pfnEtwRegisterClassicProvider', 'fifth'),
		(5, 'int (__fastcall *)(unsigned __int64) pfnEtwUnregister', 'sixth'),
	]
	
	visitor = find_all_obj_asg_visitor()
	visitor.apply_to(cfunc.body, None)
	for n, offset_name, string_nth in memory_assignment_data:
		if len(visitor.list_found_asg) <= n:
			return
		asg_expr = visitor.list_found_asg[n]
		rename_offset(asg_expr.x.obj_ea, offset_name)
	
	# Clear the decompilation caches to force the usage of the type _WPP_TRACE_API_SUITE
	ida_hexrays.clear_cached_cfuncs()

def rename_function_memset():
	memset_size = 0x68
	memset_patterns = [
	'12 1F 03 46 1A DB 11 F0 FF 01 41 EA 01 21 13 F0 03 0C 1D D1 41 EA 01 41 0C 3A 8C 46'
	]
	function_address = ida_bytes.find_bytes(
		memset_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'void *__fastcall memset(void *dest, int c, size_t count)', force=True)

def rename_function_memcmp():
	memcmp_size = 0x9C
	memcmp_patterns = [
	'04 2A ?? ?? 40 EA 01 03 13 F0 01 0F ?? ?? 13 F0 02 0F ?? ?? 12 1F ?? ?? 50 F8 04 3B'
	]
	function_address = ida_bytes.find_bytes(
		memcmp_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'int __fastcall memcmp(const void *buffer1, const void *buffer2, size_t count)', force=True)

def rename_function_memmove():
	memmove_size = 0x10A
	memmove_patterns = [
	'43 1A 93 42 BF F4 DC AE 10 2A 91 F8 00 F0 70 D2 DF E8 02 F0 0A 08 0B 0E 13 16 1B 20'
	]
	function_address = ida_bytes.find_bytes(
		memmove_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	# Check if the function already exists
	if ida_funcs.get_func(function_address) is None:
		#Delete existing items
		for i in range(memmove_size):
			ida_bytes.del_items(function_address + i, ida_bytes.get_item_size(function_address + i))
		#Delete parent functions (to delete existing "chunk")
		for i in range(memmove_size):
			parent_function = ida_funcs.get_func(function_address + i)
			if parent_function:
				ida_funcs.del_func(parent_function.start_ea)
		# Force disassembly of the bytes into instructions
		current_ea = function_address
		while current_ea < function_address+memmove_size:
			insn_len = idc.create_insn(current_ea)
			if insn_len <= 0:
				# Failed to disassemble instruction maybe a 'jump table for switch statement' ?
				break
			current_ea += insn_len
		# Add the function
		if not ida_funcs.add_func(function_address, function_address+memmove_size):
			return
	rename_function(function_address,'void *__fastcall memmove(void *dest, const void *src, size_t count)', force=True)
	
	memcpy_reverse_large_neon_address = idc.get_operand_value(function_address+0xFA, 0)
	if not ida_funcs.add_func(memcpy_reverse_large_neon_address, memcpy_reverse_large_neon_address+0x7C):
		return
	rename_function(memcpy_reverse_large_neon_address,'int __fastcall _memcpy_reverse_large_neon(int result, int a2, unsigned int a3)', force=True)
	
	memcpy_forward_new_patterns = [
	'91 F8 00 F0 10 2A 03 46 ?? ?? DF E8 02 F0 0A 08 0B 0E 13 16 1B 20 29 2E 37 40 4B 54'
	]
	function_address = ida_bytes.find_bytes(
		memcpy_forward_new_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'int __fastcall _memcpy_forward_new(int result, unsigned int, int)', force=True)
	
	memcpy_forward_large_integer_patterns = [
	'5F EA C3 7C 2D E9 F0 4B 0D F1 18 0B ?? ?? 11 F8 01 4B 52 1E 03 F8 01 4B 5F EA C3 7C'
	]
	function_address = ida_bytes.find_bytes(
		memcpy_forward_large_integer_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'void __fastcall _memcpy_forward_large_integer(int, char *, unsigned int, _BYTE *)', force=True)
	
	memcpy_forward_large_neon_patterns = [
	'2D E9 30 48 0D F1 08 0B 20 3A ?? ?? 20 3A 91 F8 20 F0 ?? ?? 91 F8 40 F0 20 3A 21 F9'
	]
	function_address = ida_bytes.find_bytes(
		memcpy_forward_large_neon_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'void __fastcall _memcpy_forward_large_neon(int, __int64 *, unsigned int, int)', force=True)
	
	memcpy_decide_patterns = [
	'2D E9 30 48 0D F1 08 0B EF F3 00 84 14 F0 0F 04 ?? ?? 10 EE 10 4F C4 F3 07 65 24 09'
	]
	function_address = ida_bytes.find_bytes(
		memcpy_decide_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'int __fastcall _memcpy_decide()', force=True)
	
	memcpy_forward_large_func_address = ida_bytes.get_32bit(idc.get_operand_value(function_address+0x36, 1))
	rename_offset(memcpy_forward_large_func_address,'unsigned int _memcpy_forward_large_func')
	
	memcpy_reverse_large_func_address = ida_bytes.get_32bit(idc.get_operand_value(function_address+0x3C, 1))
	rename_offset(memcpy_reverse_large_func_address,'unsigned int _memcpy_reverse_large_func')
	
	memcpy_reverse_large_integer_patterns = [
	'83 18 89 18 5F EA C3 7C 11 F8 20 FC 2D E9 F0 4B 0D F1 18 0B ?? ?? 11 F8 01 4D 52 1E'
	]
	function_address = ida_bytes.find_bytes(
		memcpy_reverse_large_integer_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'int __fastcall _memcpy_reverse_large_integer(int result, int, unsigned int)', force=True)


def rename_function_ppgsfailure():
	ppgsfailure_size = 0x14
	ppgsfailure_patterns = [
	'10 B5 6C 46 EC 46 2C F0 07 0C E5 46 ?? ?? ?? ?? A5 46 10 BD'
	]
	function_address = ida_bytes.find_bytes(
		ppgsfailure_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'void __fastcall _ppgsfailure()', force=True)
	
	security_check_cookie_address = idc.get_operand_value(function_address+12, 0)
	rename_function(security_check_cookie_address,'void __fastcall _security_check_cookie()', force=True)
	gsfailure_address = idc.get_operand_value(security_check_cookie_address+10, 0)
	rename_function(gsfailure_address,'void __fastcall __noreturn _gsfailure(unsigned int)', force=True)
	security_cookie_complement_address = ida_bytes.get_32bit(idc.get_operand_value(gsfailure_address+4, 1))
	rename_offset(security_cookie_complement_address,'unsigned int _security_cookie_complement')
	report_gsfailure_address = idc.get_operand_value(gsfailure_address+0x1C, 0)
	rename_function(report_gsfailure_address,'void __fastcall __noreturn _report_gsfailure(unsigned int StackCookie)', force=True)
	
	GSHandlerCheck_patterns = [
	'2D E9 00 48 EB 46 DB 69 1B 68 33 F0 03 02 50 58 13 F0 01 0F'
	]
	function_address = ida_bytes.find_bytes(
		GSHandlerCheck_patterns[0],
		idc.get_inf_attr(idc.INF_MIN_EA),
		range_end=idc.get_inf_attr(idc.INF_MAX_EA),
		flags=ida_bytes.BIN_SEARCH_FORWARD,
		radix=16
	)
	if function_address == idc.BADADDR:
		return
	rename_function(function_address,'int __fastcall _GSHandlerCheck(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord, _DISPATCHER_CONTEXT *DispatcherContext)', force=True)

def rename_function_jumps(imported_function_proto):
	imported_function_name = extract_function_name_from_proto(imported_function_proto)
	imported_function_address = get_imported_function_address(imported_function_name)
	if imported_function_address == idc.BADADDR:
		return
	
	code_xrefs = [
		xref for xref in idautils.XrefsTo(imported_function_address)
			if xref.type in [
				ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
			]
	]
	xrefs_list = list(code_xrefs)  # Convert the generator to a list
	if len(xrefs_list) < 1:
		# Function is never called
		return
	
	jump_function_proto = imported_function_proto.replace(imported_function_name, 'jump_'+imported_function_name)
	
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		if (function.end_ea - function.start_ea) == 0x0C:
			rename_function(function.start_ea, jump_function_proto) # add a suffix to the jump_function name if it already exists

def rename_function_WppTraceCallback():
	WppInitKm_address = idc.get_name_ea_simple('WppInitKm')
	if WppInitKm_address == idc.BADADDR:
		return
	
	# Decompile the function to find an assignment
	cfunc = ida_hexrays.decompile(WppInitKm_address,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_asg_type_visitor(WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME, 'Callback')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, 'int __fastcall WppTraceCallback(int MinorFunction, void *DataPath, unsigned int BufferLength, void *Buffer, void *Context, unsigned int *Size)')

def rename_functions_EventWrite():
	EtwWrite_address = get_imported_function_address('EtwWrite')
	if EtwWrite_address == idc.BADADDR:
		return
	rename_function(EtwWrite_address, 'int __fastcall EtwWrite(unsigned __int64 RegHandle, const _EVENT_DESCRIPTOR *EventDescriptor, const _GUID *ActivityId, unsigned int UserDataCount, unsigned int *UserData)', force=True)
	# List comprehension to collect only code xrefs (because we can have multiple Xrefs for the same call)
	code_xrefs = [
		xref for xref in idautils.XrefsTo(EtwWrite_address)
		if xref.type in [
			ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
		]
	]
	count = 0
	for xref in code_xrefs:
		function = ida_funcs.get_func(xref.frm)
		count += 1
		# Decompile the function to force the generation of its prototype
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		current_proto = idc.get_type(function.start_ea)
		# Find the index of the fourth comma (we will overwrite the 4 first parameters of the function)
		# The find() method's second argument is the starting index for the search.
		first_comma = current_proto.find(',')
		if first_comma != -1:
			second_comma = current_proto.find(',', first_comma + 1)
			if second_comma != -1:
				third_comma = current_proto.find(',', second_comma + 1)
				if third_comma != -1:
					fourth_comma = current_proto.find(',', third_comma + 1)
					if fourth_comma != -1:
						# Extract the substring using slicing from that index to the end
						end_proto = current_proto[fourth_comma+1:]
						rename_function(function.start_ea, f'int __fastcall EventWrite_{count:02}(unsigned __int64 RegHandle, const _EVENT_DESCRIPTOR *EventDescriptor, const _GUID *ActivityId,{end_proto}')
						continue
					else:
						# There is only 4 parameters
						rename_function(function.start_ea, f'int __fastcall EventWrite_{count:02}(unsigned __int64 RegHandle, const _EVENT_DESCRIPTOR *EventDescriptor, const _GUID *ActivityId)')
		# There is less than 4 parameters
		rename_function(function.start_ea, f'EventWrite_{count:02}')

def rename_functions_DoTraceMessage():
	WppTraceMessage_address = idc.get_name_ea_simple('pfnWppTraceMessage')
	if WppTraceMessage_address == idc.BADADDR:
		return
	# List comprehension to collect only code xrefs (because we can have multiple Xrefs for the same call)
	code_xrefs = [
		xref for xref in idautils.XrefsTo(WppTraceMessage_address)
		if xref.type in [
			ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
		]
	]
	function_count = 0
	guid_count = 0
	for xref in code_xrefs:
		function = ida_funcs.get_func(xref.frm)
		function_count += 1
		new_function_name = f'DoTraceMessage_{function_count:02}'
		rename_function(function.start_ea, new_function_name) # We don't change the prototype of the function
		# Decompile the function to searh the GUID parameter of WppTraceMessage
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('pfnWppTraceMessage')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to pfnWppTraceMessage
		if call_expr.a.size() < 2: 
			print("The function call does not have a 3rd parameter.")
			return
		param_expr = call_expr.a[2] # Because 0-based index
		if param_expr.op == idaapi.cot_ref and param_expr.x.op == idaapi.cot_obj:
			current_name = idc.get_name(param_expr.x.obj_ea)
			if current_name.find("WPP_Traceguids_") == -1:
				guid_count += 1
				rename_offset(param_expr.x.obj_ea, f'_GUID WPP_Traceguids_{guid_count:02}')

def rename_callback(function_name, cfunc, structure_name, structure_member_name, callback_prototype):
	visitor = find_asg_type_visitor(structure_name, structure_member_name)
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, callback_prototype)
				return
	print(f"Failed: Rename callback assigned to '{structure_name}.{structure_member_name}' in function '{function_name}': assignment not found!")

def rename_callbacks_WdfDeviceInitSetPnpPowerEventCallbacks():
	wdf_function_address = find_wdf_function_address('WdfDeviceInitSetPnpPowerEventCallbacks')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceInitSetPnpPowerEventCallbacks is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceInitSetPnpPowerEventCallbacks
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceInitSetPnpPowerEventCallbacks')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceInitSetPnpPowerEventCallbacks
		
		# Access the 3th parameter (PnpPowerEventCallbacks) and change its type.
		apply_structure_to_stack_parameter('WdfDeviceInitSetPnpPowerEventCallbacks', function.start_ea, call_expr, 2, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, "PnpPowerEventCallbacks")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignments of PnpPowerEventCallbacks
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceD0Entry', "NTSTATUS __fastcall EvtWdfDeviceD0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceD0EntryPostInterruptsEnabled', "NTSTATUS __fastcall EvtWdfDeviceD0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceD0Exit', "NTSTATUS __fastcall EvtWdfDeviceD0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceD0ExitPreInterruptsDisabled', "NTSTATUS __fastcall EvtWdfDeviceD0ExitPreInterruptsDisabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDevicePrepareHardware', "NTSTATUS __fastcall EvtWdfDevicePrepareHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw, WDFCMRESLIST ResourcesTranslated)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceReleaseHardware', "NTSTATUS __fastcall EvtWdfDeviceReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSelfManagedIoCleanup', "void __fastcall EvtWdfDeviceSelfManagedIoCleanup(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSelfManagedIoFlush', "void __fastcall EvtWdfDeviceSelfManagedIoFlush(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSelfManagedIoInit', "NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoInit(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSelfManagedIoSuspend', "NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoSuspend(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSelfManagedIoRestart', "NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoRestart(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceSurpriseRemoval', "void __fastcall EvtWdfDeviceSurpriseRemoval(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceQueryRemove', "NTSTATUS __fastcall EvtWdfDeviceQueryRemove(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceQueryStop', "NTSTATUS __fastcall EvtWdfDeviceQueryStop(WDFDEVICE Device)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceUsageNotification', "void __fastcall EvtWdfDeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceRelationsQuery', "void __fastcall EvtWdfDeviceRelationsQuery(WDFDEVICE Device, DEVICE_RELATION_TYPE RelationType)")
		rename_callback(function_name, cfunc, WDF_PNPPOWER_EVENT_CALLBACKS_STRUCT_NAME, 'EvtDeviceUsageNotificationEx', "NTSTATUS __fastcall EvtWdfDeviceUsageNotificationEx(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath)")

def rename_callbacks_WdfDeviceInitSetFileObjectConfig():
	wdf_function_address = find_wdf_function_address('WdfDeviceInitSetFileObjectConfig')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceInitSetFileObjectConfig is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceInitSetFileObjectConfig
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceInitSetFileObjectConfig')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceInitSetFileObjectConfig
		
		# Access the 3th parameter (FileObjectConfig) and change its type.
		apply_structure_to_stack_parameter('WdfDeviceInitSetFileObjectConfig', function.start_ea, call_expr, 2, WDF_FILEOBJECT_CONFIG_STRUCT_NAME, "FileObjectConfig")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignments of FileObjectConfig
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		
		rename_callback(function_name, cfunc, WDF_FILEOBJECT_CONFIG_STRUCT_NAME, 'EvtDeviceFileCreate', "void __fastcall EvtWdfDeviceFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)")
		rename_callback(function_name, cfunc, WDF_FILEOBJECT_CONFIG_STRUCT_NAME, 'EvtFileClose', "void __fastcall EvtWdfFileClose(WDFFILEOBJECT FileObject)")
		rename_callback(function_name, cfunc, WDF_FILEOBJECT_CONFIG_STRUCT_NAME, 'EvtFileCleanup', "void __fastcall EvtWdfFileCleanup(WDFFILEOBJECT FileObject)")

def rename_callbacks_WdfDeviceCreate():
	wdf_function_address = find_wdf_function_address('WdfDeviceCreate')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceCreate is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceCreate')
		visitor.apply_to(cfunc.body, None)
		call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceCreate
		
		# Access the 3th parameter (DeviceAttributes) and change its type.
		apply_structure_to_stack_parameter('WdfDeviceCreate', function.start_ea, call_expr, 2, WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, "DeviceAttributes")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignments of DeviceAttributes
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		
		rename_callback(function_name, cfunc, WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, 'EvtCleanupCallback', "void __fastcall EvtWdfObjectContextCleanup(WDFOBJECT Object)")
		rename_callback(function_name, cfunc, WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, 'EvtDestroyCallback', "void __fastcall EvtWdfObjectContextDestroy(WDFOBJECT Object)")

def rename_callbacks_WdfIoQueueCreate():
	wdf_function_address = find_wdf_function_address('WdfIoQueueCreate')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfIoQueueCreate is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfIoQueueCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfIoQueueCreate')
		visitor.apply_to(cfunc.body, None)
		for call_expr,_ in visitor.list_found_call:
			# Access the 3th parameter (DeviceAttributes) and change its type.
			apply_structure_to_stack_parameter('WdfIoQueueCreate', function.start_ea, call_expr, 2, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, "Config")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignments of Config
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoDefault', "void __fastcall EvtWdfIoQueueIoDefault(WDFQUEUE Queue, WDFREQUEST Request)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoRead', "void __fastcall EvtWdfIoQueueIoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoWrite', "void __fastcall EvtWdfIoQueueIoWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoDeviceControl', "void __fastcall EvtWdfIoQueueIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoInternalDeviceControl', "void __fastcall EvtWdfIoQueueIoInternalDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoStop', "void __fastcall EvtWdfIoQueueIoStop(WDFQUEUE Queue, WDFREQUEST Request, ULONG ActionFlags)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoResume', "void __fastcall EvtWdfIoQueueIoResume(WDFQUEUE Queue, WDFREQUEST Request)")
		rename_callback(function_name, cfunc, WDF_IO_QUEUE_CONFIG_STRUCT_NAME, 'EvtIoCanceledOnQueue', "void __fastcall EvtWdfIoQueueIoCanceledOnQueue(WDFQUEUE Queue, WDFREQUEST Request)")

def rename_GUID_interface():
	wdf_function_address = find_wdf_function_address('WdfDeviceCreateDeviceInterface')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceCreateDeviceInterface is never called
		return
	count = 0
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfIoQueueCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceCreateDeviceInterface')
		visitor.apply_to(cfunc.body, None)
		for call_expr,_ in visitor.list_found_call:
			if call_expr.a.size() < 3:
				# the function 'WdfDeviceCreateDeviceInterface' does not have a 3rd parameter
				return
			param_expr = call_expr.a[2]
			if param_expr.op == idaapi.cot_ref: # pointer
				param_expr = param_expr.x
			if param_expr.op == idaapi.cot_obj:
				if not is_renamed_offset(param_expr.obj_ea):
					rename_offset(param_expr.obj_ea, f'GUID InterfaceClassGUID_{count:02}')
					count += 1

def rename_callbacks_WdfDeviceAddQueryInterface():
	wdf_function_address = find_wdf_function_address('WdfDeviceAddQueryInterface')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceAddQueryInterface is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceAddQueryInterface
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceAddQueryInterface')
		visitor.apply_to(cfunc.body, None)
		for call_expr,_ in visitor.list_found_call:
			# Access the 3th parameter (InterfaceConfig) and change its type.
			apply_structure_to_stack_parameter('WdfDeviceAddQueryInterface', function.start_ea, call_expr, 2, WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME, "InterfaceConfig")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignment of InterfaceType
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_asg_type_visitor(WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME, 'InterfaceType')
		visitor.apply_to(cfunc.body, None)
		asg_expr = visitor.found_asg
		if asg_expr:
			right_asg_expr = asg_expr.y
			if right_asg_expr.op == idaapi.cot_cast: # there is a cast
				right_asg_expr = right_asg_expr.x
			if right_asg_expr.op == idaapi.cot_ref: # there is a pointer
				right_asg_expr = right_asg_expr.x
			if right_asg_expr.op == idaapi.cot_obj:
					rename_offset(right_asg_expr.obj_ea, 'GUID_query_interface')
		
		action = f"Find the variable assigned to {WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME}.interface in the function '{function_name}'"
		# Find the assignment of Interface
		visitor = find_asg_type_visitor(WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME, 'Interface')
		visitor.apply_to(cfunc.body, None)
		asg_expr = visitor.found_asg
		if asg_expr:
			right_asg_expr = asg_expr.y
			if right_asg_expr.op == idaapi.cot_cast: # there is a cast
				right_asg_expr = right_asg_expr.x
			if right_asg_expr.op == idaapi.cot_ref: # there is a pointer
				right_asg_expr = right_asg_expr.x
			if right_asg_expr.op == idaapi.cot_var and right_asg_expr.v.getv().is_stk_var():
				variable_name = right_asg_expr.v.getv().name
				variable_stack_frame_offset = right_asg_expr.v.getv().get_stkoff()
			else:
				print(f"Failed: {action}: The member 'Interface' of the structure is not assigned to a stack frame variable!")
				return
		else:
			print(f"Failed: {action}: Could not find an assignment!")
			return
		print(f"Done  : {action}")
		
		action = f"Find the size of QUERY_INTERFACE in the function '{function_name}'"
		# Find the assignment of the stack frame variable with a numerical value > 0
		visitor = find_all_asg_name_visitor(variable_name)
		visitor.apply_to(cfunc.body, None)
		interface_size = 0
		for asg_expr in visitor.list_found_asg:
			right_asg_expr = asg_expr.y
			if right_asg_expr.op == idaapi.cot_num :
				if right_asg_expr.numval() > 0:
					interface_size = right_asg_expr.numval()
					break
			else:
				print(f"Failed: {action}: '{variable_name}' in the function '{function_name}' is not assigned to a number.")
				return
		if interface_size ==0:
				print(f"Failed: {action}: Could not find a assignment of '{variable_name}' in the function '{function_name}' with a value > 0.")
				return
		print(f"Done  : {action}")
		
		# Create a new structure for the interface
		action = "Create structure 'QUERY_INTERFACE'"
		struc_id = idc.add_struc(-1, 'QUERY_INTERFACE', 0) # -1 adds it at the end, 0 means not a union
		if struc_id == idc.BADADDR:
			print(f"Failed: {action}")
			return
		idc.add_struc_member(struc_id, 'Size', 0x00, idc.FF_WORD, -1, 2)
		idc.add_struc_member(struc_id, 'Version', 0x02, idc.FF_WORD, -1, 2)
		idc.add_struc_member(struc_id, 'Context', 0x04, idc.FF_DWORD, -1, 4)
		idc.add_struc_member(struc_id, 'InterfaceReference', 0x08, idc.FF_DWORD, -1, 4)
		idc.add_struc_member(struc_id, 'InterfaceDereference', 0x0C, idc.FF_DWORD, -1, 4)
		structure_offset = 0x10
		while structure_offset < interface_size:
			interfaceFunction_count = int((structure_offset-0x10)/4)
			idc.add_struc_member(struc_id, f'InterfaceFunction_{interfaceFunction_count:02}', structure_offset, idc.FF_DWORD, -1, 4)
			structure_offset += 4
		print(f"Done  : {action}")
		
		action = f"Apply structure QUERY_INTERFACE in the stack frame of the function '{function_name}' at the offset {hex(variable_stack_frame_offset)}"
		frame_id = idc.get_frame_id(function.start_ea)
		#Delete existing members of the stack frame
		for i in range(interface_size-1):
			idc.del_struc_member(frame_id, variable_stack_frame_offset + i)
		result = idc.add_struc_member(frame_id, 'query_interface', variable_stack_frame_offset, idc.FF_STRUCT|idc.FF_DATA, struc_id, interface_size)
		if result != 0:
			print(f"Failed: {action}: Error code {result}!")
			return
		print(f"Done  : {action}")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignments of query_interface
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		
		interfaceFunction_count = 0
		while interfaceFunction_count < int((interface_size-0x10)/4):
			rename_callback(function_name, cfunc, 'QUERY_INTERFACE', f'InterfaceFunction_{interfaceFunction_count:02}', f'InterfaceFunction_{interfaceFunction_count:02}')
			interfaceFunction_count += 1

def create_object_contextes():
	wdf_function_address = find_wdf_function_address('WdfObjectGetTypedContextWorker')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfObjectGetTypedContextWorker is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfObjectGetTypedContextWorker
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfObjectGetTypedContextWorker')
		visitor.apply_to(cfunc.body, None)
		for call_expr, asg_citem in visitor.list_found_call:
			if call_expr.a.size() < 3:
				# the function 'WdfObjectGetTypedContextWorker' does not have a 3rd parameter
				continue
			param_expr = call_expr.a[2]
			if param_expr.op == idaapi.cot_ref: # pointer
				param_expr = param_expr.x
			structure_name = None
			if param_expr.op == idaapi.cot_obj:
				structure_name = rename_wdf_context_type_info(param_expr.obj_ea)
			elif param_expr.op == idaapi.cot_memref and param_expr.x.op == idaapi.cot_obj: # pointer to an already created structure
				ContextTypeInfo_structure_address = param_expr.x.obj_ea
				context_name_address = ida_bytes.get_32bit(ContextTypeInfo_structure_address+4) # Read the value of the pointer to the name of the context
				structure_name = idc.get_strlit_contents(context_name_address).decode('utf-8') # Theoretically, we already created a structure having the same name as the context 
			if structure_name != None and idc.get_struc_id(structure_name) != idc.BADADDR and asg_citem and asg_citem.is_expr():
				# Try to change the type of the variable assigned by WdfObjectGetTypedContextWorker
				# Usually, it's a register instead of a stack frame variable.
				asg_expr = asg_citem.cexpr
				if asg_expr:
					action=f"Change the type of the variable '{structure_name}* {asg_expr.x.v.getv().name}' in function '{function_name}'."
					struct_tinfo = idaapi.tinfo_t()
					struct_tinfo.get_named_type(None, structure_name)
					ptr_struct_tinfo = idaapi.tinfo_t()
					ptr_struct_tinfo.create_ptr(struct_tinfo) # create a type pointer to the structure
					# print(f"ptr_struct_tinfo={ptr_struct_tinfo}")
					# print(f"present={ptr_struct_tinfo.present()}")
					# print(f"is_correct={ptr_struct_tinfo.is_correct()}")
					# print(f"result accepts_type = {asg_expr.x.v.getv().accepts_type(ptr_struct_tinfo)}")
					if asg_expr.x.v.getv().set_lvar_type(ptr_struct_tinfo, True): # may_fail=True
						print(f"Done  : {action}")
					else:
						print(f"Failed: {action}")
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)

def cast_WDF_functions():
	wdf_function_address = find_wdf_function_address('WdfDeviceInitSetIoType')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		# WdfDeviceInitSetPnpPowerEventCallbacks is never called
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to the WDF function
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceInitSetIoType')
		visitor.apply_to(cfunc.body, None)
		for call_expr,_ in visitor.list_found_call:
			if call_expr.x.op  == idaapi.cot_cast:
				print(f"type={call_expr.x.type}")
				new_type_info = idaapi.tinfo_t()
				new_type_info.get_named_type(None, "void __fastcall WdfDeviceInitSetIoType(int todo, WDFDEVICE_INIT* DeviceInit, WDF_DEVICE_IO_TYPE IoType)")
				print(f"new type={new_type_info}")
				call_expr.x.type.swap(new_type_info)
				print(f"swap type={call_expr.x.type}")

def rename_functions_and_offsets():
	
	action = "Find FxDriverEntry"
	
	# Get the address of the main entry point
	entry_point_address = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
	
	# Get the function containing the entry point address
	entry_function = ida_funcs.get_func(entry_point_address)
	
	FxDriverEntry_size = 28
	FxDriverEntry_patterns = [
	'2D E9 30 48 0D F1 08 0B 0C 46 05 46 ?? ?? ?? ?? 21 46 28 46 ?? ?? ?? ?? BD E8 30 88',
	'2D E9 30 48 0D F2 08 0B 0C 46 05 46 ?? ?? ?? ?? 21 46 28 46 ?? ?? ?? ?? BD E8 30 88'
	]
	
	if (entry_function.end_ea - entry_function.start_ea) == FxDriverEntry_size:
			if (
				entry_function.start_ea == ida_bytes.find_bytes(FxDriverEntry_patterns[0], entry_function.start_ea, range_end=entry_function.end_ea, flags=ida_bytes.BIN_SEARCH_FORWARD,radix=16)
				or 
				entry_function.start_ea == ida_bytes.find_bytes(FxDriverEntry_patterns[1], entry_function.start_ea, range_end=entry_function.end_ea, flags=ida_bytes.BIN_SEARCH_FORWARD,radix=16)
				):
				print(f"Done  : {action}")
			else:
				print(f"Failed: {action}: Function not found!")
				return
	
	rename_function(entry_point_address, 'int __fastcall FxDriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)', force=True)
	
	# Get the destination address of the first operand (operand 0)
	# of the instruction at bl_instruction_address.
	security_init_cookie_address = idc.get_operand_value(entry_point_address+12, 0) #TODO: find opcode instead of relying on an offset
	rename_offset(security_init_cookie_address, 'unsigned int __security_init_cookie')
	FxDriverEntryWorker_address = idc.get_operand_value(entry_point_address+20, 0)
	rename_function(FxDriverEntryWorker_address, 'int __fastcall FxDriverEntryWorker(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)', force=True)
	
	# Get the address of the function by its name
	FxDriverEntryWorker_address = idc.get_name_ea_simple('FxDriverEntryWorker')
	DriverEntry_address = idc.get_operand_value(FxDriverEntryWorker_address+16, 0)
	rename_function(DriverEntry_address, 'int __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)', force=True)
	WdfDriverStubRegistryPathBuffer_address = ida_bytes.get_32bit(idc.get_operand_value(FxDriverEntryWorker_address+0x26, 1))
	rename_offset(WdfDriverStubRegistryPathBuffer_address, 'wchar_t WdfDriverStubRegistryPathBuffer[260]')
	WdfVersionBind0_address = idc.get_operand_value(FxDriverEntryWorker_address+0x42, 0)
	rename_function(WdfVersionBind0_address, 'int WdfVersionBind_0()', force=True)
	FxStubBindClasses_address = idc.get_operand_value(FxDriverEntryWorker_address+0x4e, 0)
	rename_function(FxStubBindClasses_address, 'int __fastcall FxStubBindClasses(_WDF_BIND_INFO *WdfBindInfo)', force=True)
	FxStubInitTypes_address = idc.get_operand_value(FxDriverEntryWorker_address+0x58, 0)
	rename_function(FxStubInitTypes_address, 'int __fastcall FxStubInitTypes()', force=True)
	FxStubDriverUnloadCommon_address = idc.get_operand_value(FxDriverEntryWorker_address+0xa2, 0)
	rename_function(FxStubDriverUnloadCommon_address, 'void __fastcall FxStubDriverUnloadCommon()', force=True)
	FxStubDriverUnload_address = ida_bytes.get_32bit(idc.get_operand_value(FxDriverEntryWorker_address+0x82, 1))-1
	rename_function(FxStubDriverUnload_address, 'void __fastcall FxStubDriverUnload(_DRIVER_OBJECT *DriverObject)', force=True)
	
	FxStubUnbindClasses_address = idc.get_operand_value(FxStubDriverUnloadCommon_address+0x08, 0)
	rename_function(FxStubUnbindClasses_address, 'void __fastcall FxStubUnbindClasses(_WDF_BIND_INFO *WdfBindInfo)', force=True)
	WdfVersionUnbind0_address = idc.get_operand_value(FxStubDriverUnloadCommon_address+0x12, 0)
	rename_function(WdfVersionUnbind0_address, 'int WdfVersionUnbind_0()', force=True)
	
	WdfVersionUnbindClass0_address = idc.get_operand_value(FxStubUnbindClasses_address+0x36, 0)
	rename_function(WdfVersionUnbindClass0_address, 'int WdfVersionUnbindClass_0()', force=True)
	
	WdfVersionBindClass0_address = idc.get_operand_value(FxStubBindClasses_address+0x4a, 0)
	rename_function(WdfVersionBindClass0_address, 'int WdfVersionBindClass_0()', force=True)
	
	action = "Find the function calling 'WdfDriverCreate'"
	# Usually, this is the 'DriverEntry' function
	WdfDriverCreate_address = find_wdf_function_address('WdfDriverCreate')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(WdfDriverCreate_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		print("Failed: {action}: WdfDriverCreate is never called!")
		return
	if len(xrefs_list) > 1:
		print("Failed: {action}: WdfDriverCreate is called more than once!")
		return
	xref = xrefs_list[0]
	# Get the function object containing the target address
	function = ida_funcs.get_func(xref.frm)
	function_name = idc.get_func_name(function.start_ea)
	
	# Decompile the function to find the call to WdfDriverCreate
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_all_call_visitor('WdfDriverCreate')
	visitor.apply_to(cfunc.body, None)
	call_expr,_ = visitor.list_found_call[0] # We expect exactly one call to WdfDriverCreate
	print(f"Done  : {action}")
	
	# Access the 3th parameter (DriverAttributes) and change its type.
	apply_structure_to_stack_parameter('WdfDriverCreate', function.start_ea, call_expr, 3, WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, "DriverAttributes")
	
	# Access the 4th parameter (DriverConfig) and change its type.
	apply_structure_to_stack_parameter('WdfDriverCreate', function.start_ea, call_expr, 4, WDF_DRIVER_CONFIG_STRUCT_NAME, "DriverConfig")
	
	# Invalidate the decompilation cache and close all related pseudocode windows.
	ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
	
	# Decompile again the function to find the assignments of DriverAttributes and DriverConfig
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	
	visitor = find_asg_type_visitor(WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, 'ContextTypeInfo')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast from void* to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_wdf_context_type_info(asg_expr.y.x.obj_ea)
	
	visitor = find_asg_type_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverDeviceAdd')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, 'NTSTATUS __fastcall EvtDriverDeviceAdd(WDFDRIVER *Driver, WDFDEVICE_INIT *DeviceInit)')
	
	visitor = find_asg_type_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverUnload')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, 'void __fastcall EvtDriverUnload(WDFDRIVER *Driver)')
	
	rename_function_McGenEventRegister()
	rename_function_McGenEventUnregister()
	rename_function_WppInitKm_and_WppCleanupKm()
	rename_offset_WPP_CONTROL_GUID()
	rename_function_WppLoadTracingSupport()
	rename_function_memset()
	rename_function_memmove()
	rename_function_memcmp()
	rename_function_ppgsfailure()
	rename_function_jumps('size_t __fastcall strlen(const char *str)')
	rename_function_jumps('int __fastcall strncmp(const char *string1, const char *string2, size_t count)')
	rename_function_jumps('int __fastcall strcmp(const char *string1, const char *string2)')
	rename_function_WppTraceCallback()
	rename_functions_EventWrite()
	rename_functions_DoTraceMessage()
	rename_callbacks_WdfDeviceInitSetPnpPowerEventCallbacks()
	rename_callbacks_WdfDeviceInitSetFileObjectConfig()
	rename_callbacks_WdfDeviceCreate()
	rename_callbacks_WdfIoQueueCreate()
	rename_GUID_interface()
	rename_callbacks_WdfDeviceAddQueryInterface()
	create_object_contextes()
	#cast_WDF_functions()