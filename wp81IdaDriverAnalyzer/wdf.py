import ida_bytes
import idaapi
import idc
import ida_search
import ida_struct
import idautils
import ida_funcs
import ida_hexrays
import ida_entry
import ida_xref
import ida_typeinf
import ida_enum
import re

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
	"WdfChildListCreate",
	"WdfChildListGetDevice",
	"WdfChildListRetrievePdo",
	"WdfChildListRetrieveAddressDescription",
	"WdfChildListBeginScan",
	"WdfChildListEndScan",
	"WdfChildListBeginIteration",
	"WdfChildListRetrieveNextDevice",
	"WdfChildListEndIteration",
	"WdfChildListAddOrUpdateChildDescriptionAsPresent",
	"WdfChildListUpdateChildDescriptionAsMissing",
	"WdfChildListUpdateAllChildDescriptionsAsPresent",
	"WdfChildListRequestChildEject",
	"WdfCollectionCreate",
	"WdfCollectionGetCount",
	"WdfCollectionAdd",
	"WdfCollectionRemove",
	"WdfCollectionRemoveItem",
	"WdfCollectionGetItem",
	"WdfCollectionGetFirstItem",
	"WdfCollectionGetLastItem",
	"WdfCommonBufferCreate",
	"WdfCommonBufferGetAlignedVirtualAddress",
	"WdfCommonBufferGetAlignedLogicalAddress",
	"WdfCommonBufferGetLength",
	"WdfControlDeviceInitAllocate",
	"WdfControlDeviceInitSetShutdownNotification",
	"WdfControlFinishInitializing",
	"WdfDeviceGetDeviceState",
	"WdfDeviceSetDeviceState",
	"WdfWdmDeviceGetWdfDeviceHandle",
	"WdfDeviceWdmGetDeviceObject",
	"WdfDeviceWdmGetAttachedDevice",
	"WdfDeviceWdmGetPhysicalDevice",
	"WdfDeviceWdmDispatchPreprocessedIrp",
	"WdfDeviceAddDependentUsageDeviceObject",
	"WdfDeviceAddRemovalRelationsPhysicalDevice",
	"WdfDeviceRemoveRemovalRelationsPhysicalDevice",
	"WdfDeviceClearRemovalRelationsDevices",
	"WdfDeviceGetDriver",
	"WdfDeviceRetrieveDeviceName",
	"WdfDeviceAssignMofResourceName",
	"WdfDeviceGetIoTarget",
	"WdfDeviceGetDevicePnpState",
	"WdfDeviceGetDevicePowerState",
	"WdfDeviceGetDevicePowerPolicyState",
	"WdfDeviceAssignS0IdleSettings",
	"WdfDeviceAssignSxWakeSettings",
	"WdfDeviceOpenRegistryKey",
	"WdfDeviceSetSpecialFileSupport",
	"WdfDeviceSetCharacteristics",
	"WdfDeviceGetCharacteristics",
	"WdfDeviceGetAlignmentRequirement",
	"WdfDeviceSetAlignmentRequirement",
	"WdfDeviceInitFree",
	"WdfDeviceInitSetPnpPowerEventCallbacks",
	"WdfDeviceInitSetPowerPolicyEventCallbacks",
	"WdfDeviceInitSetPowerPolicyOwnership",
	"WdfDeviceInitRegisterPnpStateChangeCallback",
	"WdfDeviceInitRegisterPowerStateChangeCallback",
	"WdfDeviceInitRegisterPowerPolicyStateChangeCallback",
	"WdfDeviceInitSetIoType",
	"WdfDeviceInitSetExclusive",
	"WdfDeviceInitSetPowerNotPageable",
	"WdfDeviceInitSetPowerPageable",
	"WdfDeviceInitSetPowerInrush",
	"WdfDeviceInitSetDeviceType",
	"WdfDeviceInitAssignName",
	"WdfDeviceInitAssignSDDLString",
	"WdfDeviceInitSetDeviceClass",
	"WdfDeviceInitSetCharacteristics",
	"WdfDeviceInitSetFileObjectConfig",
	"WdfDeviceInitSetRequestAttributes",
	"WdfDeviceInitAssignWdmIrpPreprocessCallback",
	"WdfDeviceInitSetIoInCallerContextCallback",
	"WdfDeviceCreate",
	"WdfDeviceSetStaticStopRemove",
	"WdfDeviceCreateDeviceInterface",
	"WdfDeviceSetDeviceInterfaceState",
	"WdfDeviceRetrieveDeviceInterfaceString",
	"WdfDeviceCreateSymbolicLink",
	"WdfDeviceQueryProperty",
	"WdfDeviceAllocAndQueryProperty",
	"WdfDeviceSetPnpCapabilities",
	"WdfDeviceSetPowerCapabilities",
	"WdfDeviceSetBusInformationForChildren",
	"WdfDeviceIndicateWakeStatus",
	"WdfDeviceSetFailed",
	"WdfDeviceStopIdleNoTrack",
	"WdfDeviceResumeIdleNoTrack",
	"WdfDeviceGetFileObject",
	"WdfDeviceEnqueueRequest",
	"WdfDeviceGetDefaultQueue",
	"WdfDeviceConfigureRequestDispatching",
	"WdfDmaEnablerCreate",
	"WdfDmaEnablerGetMaximumLength",
	"WdfDmaEnablerGetMaximumScatterGatherElements",
	"WdfDmaEnablerSetMaximumScatterGatherElements",
	"WdfDmaTransactionCreate",
	"WdfDmaTransactionInitialize",
	"WdfDmaTransactionInitializeUsingRequest",
	"WdfDmaTransactionExecute",
	"WdfDmaTransactionRelease",
	"WdfDmaTransactionDmaCompleted",
	"WdfDmaTransactionDmaCompletedWithLength",
	"WdfDmaTransactionDmaCompletedFinal",
	"WdfDmaTransactionGetBytesTransferred",
	"WdfDmaTransactionSetMaximumLength",
	"WdfDmaTransactionGetRequest",
	"WdfDmaTransactionGetCurrentDmaTransferLength",
	"WdfDmaTransactionGetDevice",
	"WdfDpcCreate",
	"WdfDpcEnqueue",
	"WdfDpcCancel",
	"WdfDpcGetParentObject",
	"WdfDpcWdmGetDpc",
	"WdfDriverCreate",
	"WdfDriverGetRegistryPath",
	"WdfDriverWdmGetDriverObject",
	"WdfDriverOpenParametersRegistryKey",
	"WdfWdmDriverGetWdfDriverHandle",
	"WdfDriverRegisterTraceInfo",
	"WdfDriverRetrieveVersionString",
	"WdfDriverIsVersionAvailable",
	"WdfFdoInitWdmGetPhysicalDevice",
	"WdfFdoInitOpenRegistryKey",
	"WdfFdoInitQueryProperty",
	"WdfFdoInitAllocAndQueryProperty",
	"WdfFdoInitSetEventCallbacks",
	"WdfFdoInitSetFilter",
	"WdfFdoInitSetDefaultChildListConfig",
	"WdfFdoQueryForInterface",
	"WdfFdoGetDefaultChildList",
	"WdfFdoAddStaticChild",
	"WdfFdoLockStaticChildListForIteration",
	"WdfFdoRetrieveNextStaticChild",
	"WdfFdoUnlockStaticChildListFromIteration",
	"WdfFileObjectGetFileName",
	"WdfFileObjectGetFlags",
	"WdfFileObjectGetDevice",
	"WdfFileObjectWdmGetFileObject",
	"WdfInterruptCreate",
	"WdfInterruptQueueDpcForIsr",
	"WdfInterruptSynchronize",
	"WdfInterruptAcquireLock",
	"WdfInterruptReleaseLock",
	"WdfInterruptEnable",
	"WdfInterruptDisable",
	"WdfInterruptWdmGetInterrupt",
	"WdfInterruptGetInfo",
	"WdfInterruptSetPolicy",
	"WdfInterruptGetDevice",
	"WdfIoQueueCreate",
	"WdfIoQueueGetState",
	"WdfIoQueueStart",
	"WdfIoQueueStop",
	"WdfIoQueueStopSynchronously",
	"WdfIoQueueGetDevice",
	"WdfIoQueueRetrieveNextRequest",
	"WdfIoQueueRetrieveRequestByFileObject",
	"WdfIoQueueFindRequest",
	"WdfIoQueueRetrieveFoundRequest",
	"WdfIoQueueDrainSynchronously",
	"WdfIoQueueDrain",
	"WdfIoQueuePurgeSynchronously",
	"WdfIoQueuePurge",
	"WdfIoQueueReadyNotify",
	"WdfIoTargetCreate",
	"WdfIoTargetOpen",
	"WdfIoTargetCloseForQueryRemove",
	"WdfIoTargetClose",
	"WdfIoTargetStart",
	"WdfIoTargetStop",
	"WdfIoTargetGetState",
	"WdfIoTargetGetDevice",
	"WdfIoTargetQueryTargetProperty",
	"WdfIoTargetAllocAndQueryTargetProperty",
	"WdfIoTargetQueryForInterface",
	"WdfIoTargetWdmGetTargetDeviceObject",
	"WdfIoTargetWdmGetTargetPhysicalDevice",
	"WdfIoTargetWdmGetTargetFileObject",
	"WdfIoTargetWdmGetTargetFileHandle",
	"WdfIoTargetSendReadSynchronously",
	"WdfIoTargetFormatRequestForRead",
	"WdfIoTargetSendWriteSynchronously",
	"WdfIoTargetFormatRequestForWrite",
	"WdfIoTargetSendIoctlSynchronously",
	"WdfIoTargetFormatRequestForIoctl",
	"WdfIoTargetSendInternalIoctlSynchronously",
	"WdfIoTargetFormatRequestForInternalIoctl",
	"WdfIoTargetSendInternalIoctlOthersSynchronously",
	"WdfIoTargetFormatRequestForInternalIoctlOthers",
	"WdfMemoryCreate",
	"WdfMemoryCreatePreallocated",
	"WdfMemoryGetBuffer",
	"WdfMemoryAssignBuffer",
	"WdfMemoryCopyToBuffer",
	"WdfMemoryCopyFromBuffer",
	"WdfLookasideListCreate",
	"WdfMemoryCreateFromLookaside",
	"WdfDeviceMiniportCreate",
	"WdfDriverMiniportUnload",
	"WdfObjectGetTypedContextWorker",
	"WdfObjectAllocateContext",
	"WdfObjectContextGetObject",
	"WdfObjectReferenceActual",
	"WdfObjectDereferenceActual",
	"WdfObjectCreate",
	"WdfObjectDelete",
	"WdfObjectQuery",
	"WdfPdoInitAllocate",
	"WdfPdoInitSetEventCallbacks",
	"WdfPdoInitAssignDeviceID",
	"WdfPdoInitAssignInstanceID",
	"WdfPdoInitAddHardwareID",
	"WdfPdoInitAddCompatibleID",
	"WdfPdoInitAddDeviceText",
	"WdfPdoInitSetDefaultLocale",
	"WdfPdoInitAssignRawDevice",
	"WdfPdoMarkMissing",
	"WdfPdoRequestEject",
	"WdfPdoGetParent",
	"WdfPdoRetrieveIdentificationDescription",
	"WdfPdoRetrieveAddressDescription",
	"WdfPdoUpdateAddressDescription",
	"WdfPdoAddEjectionRelationsPhysicalDevice",
	"WdfPdoRemoveEjectionRelationsPhysicalDevice",
	"WdfPdoClearEjectionRelationsDevices",
	"WdfDeviceAddQueryInterface",
	"WdfRegistryOpenKey",
	"WdfRegistryCreateKey",
	"WdfRegistryClose",
	"WdfRegistryWdmGetHandle",
	"WdfRegistryRemoveKey",
	"WdfRegistryRemoveValue",
	"WdfRegistryQueryValue",
	"WdfRegistryQueryMemory",
	"WdfRegistryQueryMultiString",
	"WdfRegistryQueryUnicodeString",
	"WdfRegistryQueryString",
	"WdfRegistryQueryULong",
	"WdfRegistryAssignValue",
	"WdfRegistryAssignMemory",
	"WdfRegistryAssignMultiString",
	"WdfRegistryAssignUnicodeString",
	"WdfRegistryAssignString",
	"WdfRegistryAssignULong",
	"WdfRequestCreate",
	"WdfRequestCreateFromIrp",
	"WdfRequestReuse",
	"WdfRequestChangeTarget",
	"WdfRequestFormatRequestUsingCurrentType",
	"WdfRequestWdmFormatUsingStackLocation",
	"WdfRequestSend",
	"WdfRequestGetStatus",
	"WdfRequestMarkCancelable",
	"WdfRequestUnmarkCancelable",
	"WdfRequestIsCanceled",
	"WdfRequestCancelSentRequest",
	"WdfRequestIsFrom32BitProcess",
	"WdfRequestSetCompletionRoutine",
	"WdfRequestGetCompletionParams",
	"WdfRequestAllocateTimer",
	"WdfRequestComplete",
	"WdfRequestCompleteWithPriorityBoost",
	"WdfRequestCompleteWithInformation",
	"WdfRequestGetParameters",
	"WdfRequestRetrieveInputMemory",
	"WdfRequestRetrieveOutputMemory",
	"WdfRequestRetrieveInputBuffer",
	"WdfRequestRetrieveOutputBuffer",
	"WdfRequestRetrieveInputWdmMdl",
	"WdfRequestRetrieveOutputWdmMdl",
	"WdfRequestRetrieveUnsafeUserInputBuffer",
	"WdfRequestRetrieveUnsafeUserOutputBuffer",
	"WdfRequestSetInformation",
	"WdfRequestGetInformation",
	"WdfRequestGetFileObject",
	"WdfRequestProbeAndLockUserBufferForRead",
	"WdfRequestProbeAndLockUserBufferForWrite",
	"WdfRequestGetRequestorMode",
	"WdfRequestForwardToIoQueue",
	"WdfRequestGetIoQueue",
	"WdfRequestRequeue",
	"WdfRequestStopAcknowledge",
	"WdfRequestWdmGetIrp",
	"WdfIoResourceRequirementsListSetSlotNumber",
	"WdfIoResourceRequirementsListSetInterfaceType",
	"WdfIoResourceRequirementsListAppendIoResList",
	"WdfIoResourceRequirementsListInsertIoResList",
	"WdfIoResourceRequirementsListGetCount",
	"WdfIoResourceRequirementsListGetIoResList",
	"WdfIoResourceRequirementsListRemove",
	"WdfIoResourceRequirementsListRemoveByIoResList",
	"WdfIoResourceListCreate",
	"WdfIoResourceListAppendDescriptor",
	"WdfIoResourceListInsertDescriptor",
	"WdfIoResourceListUpdateDescriptor",
	"WdfIoResourceListGetCount",
	"WdfIoResourceListGetDescriptor",
	"WdfIoResourceListRemove",
	"WdfIoResourceListRemoveByDescriptor",
	"WdfCmResourceListAppendDescriptor",
	"WdfCmResourceListInsertDescriptor",
	"WdfCmResourceListGetCount",
	"WdfCmResourceListGetDescriptor",
	"WdfCmResourceListRemove",
	"WdfCmResourceListRemoveByDescriptor",
	"WdfStringCreate",
	"WdfStringGetUnicodeString",
	"WdfObjectAcquireLock",
	"WdfObjectReleaseLock",
	"WdfWaitLockCreate",
	"WdfWaitLockAcquire",
	"WdfWaitLockRelease",
	"WdfSpinLockCreate",
	"WdfSpinLockAcquire",
	"WdfSpinLockRelease",
	"WdfTimerCreate",
	"WdfTimerStart",
	"WdfTimerStop",
	"WdfTimerGetParentObject",
	"WdfUsbTargetDeviceCreate",
	"WdfUsbTargetDeviceRetrieveInformation",
	"WdfUsbTargetDeviceGetDeviceDescriptor",
	"WdfUsbTargetDeviceRetrieveConfigDescriptor",
	"WdfUsbTargetDeviceQueryString",
	"WdfUsbTargetDeviceAllocAndQueryString",
	"WdfUsbTargetDeviceFormatRequestForString",
	"WdfUsbTargetDeviceGetNumInterfaces",
	"WdfUsbTargetDeviceSelectConfig",
	"WdfUsbTargetDeviceWdmGetConfigurationHandle",
	"WdfUsbTargetDeviceRetrieveCurrentFrameNumber",
	"WdfUsbTargetDeviceSendControlTransferSynchronously",
	"WdfUsbTargetDeviceFormatRequestForControlTransfer",
	"WdfUsbTargetDeviceIsConnectedSynchronous",
	"WdfUsbTargetDeviceResetPortSynchronously",
	"WdfUsbTargetDeviceCyclePortSynchronously",
	"WdfUsbTargetDeviceFormatRequestForCyclePort",
	"WdfUsbTargetDeviceSendUrbSynchronously",
	"WdfUsbTargetDeviceFormatRequestForUrb",
	"WdfUsbTargetPipeGetInformation",
	"WdfUsbTargetPipeIsInEndpoint",
	"WdfUsbTargetPipeIsOutEndpoint",
	"WdfUsbTargetPipeGetType",
	"WdfUsbTargetPipeSetNoMaximumPacketSizeCheck",
	"WdfUsbTargetPipeWriteSynchronously",
	"WdfUsbTargetPipeFormatRequestForWrite",
	"WdfUsbTargetPipeReadSynchronously",
	"WdfUsbTargetPipeFormatRequestForRead",
	"WdfUsbTargetPipeConfigContinuousReader",
	"WdfUsbTargetPipeAbortSynchronously",
	"WdfUsbTargetPipeFormatRequestForAbort",
	"WdfUsbTargetPipeResetSynchronously",
	"WdfUsbTargetPipeFormatRequestForReset",
	"WdfUsbTargetPipeSendUrbSynchronously",
	"WdfUsbTargetPipeFormatRequestForUrb",
	"WdfUsbInterfaceGetInterfaceNumber",
	"WdfUsbInterfaceGetNumEndpoints",
	"WdfUsbInterfaceGetDescriptor",
	"WdfUsbInterfaceSelectSetting",
	"WdfUsbInterfaceGetEndpointInformation",
	"WdfUsbTargetDeviceGetInterface",
	"WdfUsbInterfaceGetConfiguredSettingIndex",
	"WdfUsbInterfaceGetNumConfiguredPipes",
	"WdfUsbInterfaceGetConfiguredPipe",
	"WdfUsbTargetPipeWdmGetPipeHandle",
	"WdfVerifierDbgBreakPoint",
	"WdfVerifierKeBugCheck",
	"WdfWmiProviderCreate",
	"WdfWmiProviderGetDevice",
	"WdfWmiProviderIsEnabled",
	"WdfWmiProviderGetTracingHandle",
	"WdfWmiInstanceCreate",
	"WdfWmiInstanceRegister",
	"WdfWmiInstanceDeregister",
	"WdfWmiInstanceGetDevice",
	"WdfWmiInstanceGetProvider",
	"WdfWmiInstanceFireEvent",
	"WdfWorkItemCreate",
	"WdfWorkItemEnqueue",
	"WdfWorkItemGetParentObject",
	"WdfWorkItemFlush",
	"WdfCommonBufferCreateWithConfig",
	"WdfDmaEnablerGetFragmentLength",
	"WdfDmaEnablerWdmGetDmaAdapter",
	"WdfUsbInterfaceGetNumSettings", # here ends version 1.1
	"WdfDeviceRemoveDependentUsageDeviceObject",
	"WdfDeviceGetSystemPowerAction",
	"WdfInterruptSetExtendedPolicy",
	"WdfIoQueueAssignForwardProgressPolicy",
	"WdfPdoInitAssignContainerID",
	"WdfPdoInitAllowForwardingRequestToParent",
	"WdfRequestMarkCancelableEx",
	"WdfRequestIsReserved",
	"WdfRequestForwardToParentDeviceIoQueue", # here ends version 1.5 and 1.7
	"WdfCxDeviceInitAllocate",
	"WdfCxDeviceInitAssignWdmIrpPreprocessCallback",
	"WdfCxDeviceInitSetIoInCallerContextCallback",
	"WdfCxDeviceInitSetRequestAttributes",
	"WdfCxDeviceInitSetFileObjectConfig",
	"WdfDeviceWdmDispatchIrp",
	"WdfDeviceWdmDispatchIrpToIoQueue",
	"WdfDeviceInitSetRemoveLockOptions",
	"WdfDeviceConfigureWdmIrpDispatchCallback",
	"WdfDmaEnablerConfigureSystemProfile",
	"WdfDmaTransactionInitializeUsingOffset",
	"WdfDmaTransactionGetTransferInfo",
	"WdfDmaTransactionSetChannelConfigurationCallback",
	"WdfDmaTransactionSetTransferCompleteCallback",
	"WdfDmaTransactionSetImmediateExecution",
	"WdfDmaTransactionAllocateResources",
	"WdfDmaTransactionSetDeviceAddressOffset",
	"WdfDmaTransactionFreeResources",
	"WdfDmaTransactionCancel",
	"WdfDmaTransactionWdmGetTransferContext",
	"WdfInterruptQueueWorkItemForIsr",
	"WdfInterruptTryToAcquireLock",
	"WdfIoQueueStopAndPurge",
	"WdfIoQueueStopAndPurgeSynchronously",
	"WdfIoTargetPurge",
	"WdfUsbTargetDeviceCreateWithParameters",
	"WdfUsbTargetDeviceQueryUsbCapability",
	"WdfUsbTargetDeviceCreateUrb",
	"WdfUsbTargetDeviceCreateIsochUrb",
	"WdfDeviceWdmAssignPowerFrameworkSettings",
	"WdfDmaTransactionStopSystemTransfer",
	"WdfCxVerifierKeBugCheck",
	"WdfInterruptReportActive",
	"WdfInterruptReportInactive",
	"WdfDeviceInitSetReleaseHardwareOrderOnFailure",
	"WdfGetTriageInfo", # here ends version 1.9
	"WdfDeviceInitSetIoTypeEx",
	"WdfDeviceQueryPropertyEx",
	"WdfDeviceAllocAndQueryPropertyEx",
	"WdfDeviceAssignProperty",
	"WdfFdoInitQueryPropertyEx",
	"WdfFdoInitAllocAndQueryPropertyEx" # here ends version 1.11
	]

# Address of the array containing the WDF functions
WdfFunctions_address = 0

def add_WDFFUNCTIONS_structure():
	global WdfFunctions_address
	
	# Search the KmdfLibrary
	# Encode the string to UTF-16LE
	search_string_bytes = "KmdfLibrary".encode('utf-16le')
	
	# Convert the byte string to a hex string for find_binary
	hex_pattern = "".join(f'{b:02X} ' for b in search_string_bytes)
	
	# Start searching from the beginning of the IDB.
	aKmdflibrary_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), hex_pattern, 16, ida_search.SEARCH_DOWN)
	if aKmdflibrary_address == idaapi.BADADDR:
		print(f"KmdfLibrary not found !")
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
	print(f"Found KmdfLibrary version {major}.{minor}")
	if (major!=1 or minor !=11):
		print(f"Only version 1.11 is supported by this plugin !")
		return
	
	rename_offset(ref_to_aKmdflibrary_address-4, '_WDF_BIND_INFO WdfBindInfo') # TODO define structure _WDF_BIND_INFO
	
	# check if the structure already exists
	structure_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
	if structure_id != -1:
		# delete old structure
		idc.del_struc(structure_id)
	idc.add_struc(-1, WDFFUNCTIONS_STRUCT_NAME, 0)
	structure_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
	for func_name in kmdf1_11:
		idc.add_struc_member(structure_id, func_name, idc.BADADDR, idc.FF_DATA | ida_bytes.FF_DWORD, -1, 4)
	
	# Get the address pointed by 'FuncTable'
	WdfFunctions_address = ida_bytes.get_32bit(ref_to_aKmdflibrary_address + 20)
	rename_offset(WdfFunctions_address, 'WdfFunctions')
	apply_structure_to_offset(WdfFunctions_address, WDFFUNCTIONS_STRUCT_NAME)

def find_wdf_function_address(function_name):
	"""
	Finds the offset of a structure member by name.
	"""
	struct_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
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
				ea = ida_search.find_binary(f.start_ea, f.end_ea, pattern, 16, ida_search.SEARCH_DOWN)
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

def add_others_structures():
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
		print("Error when adding local type 'wchar_t'!")
	if idc.set_local_type(-1,"typedef unsigned int size_t;", idc.PT_SIL) == 0:
		print("Error when adding local type 'size_t'!")
	if idc.set_local_type(-1,"typedef int NTSTATUS;", idc.PT_SIL) == 0:
		print("Error when adding local type 'NTSTATUS'!")
	if idc.set_local_type(-1,"typedef void *WDFOBJECT;", idc.PT_SIL) == 0:
		print("Error when adding local type 'WDFOBJECT'!")
	if idc.set_local_type(-1,"typedef unsigned int ULONG;", idc.PT_SIL) == 0:
		print("Error when adding local type 'ULONG'!")

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
		idc.add_enum_member(enum_id, member_name, member_value, ida_enum.DEFMASK)
	
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
		idc.add_enum_member(enum_id, member_name, member_value, ida_enum.DEFMASK)

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
	print(f"Try to rename function '{old_name}' to '{new_proto}': ", end='')
	if not force and is_renamed_function(function_address):
		print(f"abort because function is already renamed.")
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
		if new_function_name == wanted_new_function_name:
			print("done", end='')
		else:
			print(f"renamed to {new_function_name}", end='')
		if update_type:
			result = idc.SetType(function_address, new_proto)
			if not result:
				print(" but failed to apply proto.")
		print(".")
	else:
		print(f"failed to rename to '{wanted_new_function_name}' after {retry} retries.")

def get_structure_member_name(structure_name, member_offset):
	struc_id = ida_struct.get_struc_id(structure_name)
	struc_t = ida_struct.get_struc (struc_id)
	member_id = ida_struct.get_member_id(struc_t, member_offset)
	member_name = ida_struct.get_member_name(member_id)
	return member_name

# Iterate through a C-tree to find all the calls to a WDF function or a simple function
# The memory address of the WDF function is casted in order to be called
# example: ((int (__fastcall *)(int, int, int, int *, _WDF_DRIVER_CONFIG *, _DWORD))WdfFunctions.WdfDriverCreate)(...)
class find_all_call_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_function_name):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
		self.list_found_call = []
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
								self.list_found_call.append(expr)
				elif expr.x.x.op == idaapi.cot_memptr:
					if expr.x.x.x.op == idaapi.cot_obj:
						member_offset = expr.x.x.m
						if str(expr.x.x.x.type) == 'WDFFUNCTIONS *':
							member_name = get_structure_member_name(WDFFUNCTIONS_STRUCT_NAME, member_offset)
							if member_name == self.search_function_name:
								self.list_found_call.append(expr)
			elif expr.x.op  == idaapi.cot_obj: # Case of a call to an imported function or to another function of the driver
				object_name = idc.get_name(expr.x.obj_ea)
				if object_name == self.search_function_name:
					self.list_found_call.append(expr)
		return 0  # Continue traversal

# Iterate through a C-tree to find the assignment of a variable of a given type
class find_asg_type_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_var_type, search_var_type_member):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
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
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
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
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
		self.list_found_asg = []

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_asg:
			if expr.x.op  == idaapi.cot_obj:
				self.list_found_asg.append(expr)
		return 0  # Continue traversal

def apply_structure_to_stack_parameter(called_name, function_address, call_expr, idx_param, struct_name, new_var_name):
	
	function_name = idc.get_func_name(function_address)
	
	if call_expr.a.size() < idx_param+1: # +1 because 0-based index
		print(f"In '{function_name}', the function '{called_name}' does not have a {idx_param+1}th parameter.")
		return
	param_expr = call_expr.a[idx_param]
	if param_expr.op == idaapi.cot_ref: # &variable
		param_expr = param_expr.x
	if (param_expr.op != idaapi.cot_var) or (not param_expr.v.getv().is_stk_var()):
		print(f"In {function_name}, the {idx_param+1}th parameter of the function '{called_name}' is not a stack frame variable.")
		return
	struc_id = ida_struct.get_struc_id(struct_name)
	s = ida_struct.get_struc(struc_id)
	struc_size = ida_struct.get_struc_size(s)
	frame_id = idc.get_frame_id(function_address)
	stack_frame_offset = param_expr.v.getv().get_stkoff()
	#Delete existing members of the stack frame
	for i in range(struc_size-1):
		idc.del_struc_member(frame_id, stack_frame_offset + i)
	result = idc.add_struc_member(frame_id, new_var_name, stack_frame_offset, idc.FF_STRUCT|idc.FF_DATA, struc_id, struc_size)
	if result != 0:
		print(f"Failed to apply structure {struct_name} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}! Error code : {result}")
		return
	print(f"Applyed structure {struct_name} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}.")

def rename_offset(offset_address, new_definition):
	old_name = idc.get_name(offset_address)
	print(f"Try to rename '{old_name}' to '{new_definition}': ", end='')
	matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', new_definition)
	if matches:
		wanted_new_name = matches[-1] # get the last match of the capturing group
	else:
		print(f"abort, because no name found in {new_definition}.")
		return
	
	retry = 0
	new_name = wanted_new_name
	while old_name!=new_name and idc.get_name_ea_simple(new_name)!=idc.BADADDR and retry < 5:
		new_name += '_'
		retry += 1
	
	if retry < 5:
		idc.set_name(offset_address, new_name)
		if new_name == wanted_new_name:
			print("done", end='')
		else:
			print(f"renamed to {new_name}", end='')
		if wanted_new_name != new_definition: # there's some type definition in addition to the name.
			new_type = new_definition.replace(wanted_new_name,'') # remove the name to have a correct type.
			result = idc.SetType(offset_address, new_type)
			if not result:
				print(" but failed to apply type.")
		print(".")
	else:
		print(f"failed to rename to '{wanted_new_name}' after {retry} retries.")


def apply_structure_to_offset(offset_address, struct_name):
	struc_id = ida_struct.get_struc_id(struct_name)
	s = ida_struct.get_struc(struc_id)
	struc_size = ida_struct.get_struc_size(s)
	#Delete existing items
	for i in range(struc_size-1):
		ida_bytes.del_items(offset_address + i, ida_bytes.get_item_size(offset_address + i))
	# Apply the structure to the memory address
	result = ida_bytes.create_struct(offset_address, struc_size, struc_id, True) #Force=True
	if result != True:
		print(f"Failed to apply structure {struct_name} at the offset {hex(offset_address)}!")
		return
	print(f"Applyed structure {struct_name} at the offset {hex(offset_address)}.")

def rename_wdf_context_type_info(ContextTypeInfo_address):
	ContextTypeInfo_structure_address = ida_bytes.get_32bit(ContextTypeInfo_address)
	apply_structure_to_offset(ContextTypeInfo_structure_address, WDF_OBJECT_CONTEXT_TYPE_INFO_STRUCT_NAME)
	context_name_address = ida_bytes.get_32bit(ContextTypeInfo_structure_address+4) #Read the value of the pointer to the name of the context
	context_size = ida_bytes.get_32bit(ContextTypeInfo_structure_address+8)
	context_name = idc.get_strlit_contents(context_name_address).decode('utf-8')
	ContextTypeInfo_structure_name = "WDF_"+context_name+"_TYPE_INFO"
	rename_offset(ContextTypeInfo_structure_address, "_WDF_OBJECT_CONTEXT_TYPE_INFO "+ContextTypeInfo_structure_name)
	
	# Create the structure of the context
	# Check if the structure already exists
	struc_id = idc.get_struc_id(context_name)
	if struc_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struc_id)
	# Create a new structure
	struc_id = idc.add_struc(-1, context_name, 0) # -1 adds it at the end, 0 means not a union
	if struc_id == idc.BADADDR:
		print(f"Failed to create structure '{context_name}'!")
		return
	for idx in range(context_size):
		idc.add_struc_member(struc_id, f"field_{idx:x}", idx, idc.FF_BYTE | idc.FF_DATA, -1,1)

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
	call_expr = visitor.list_found_call[0] # We expect exactly one call to EtwRegister
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
		call_expr = visitor.list_found_call[0] # We expect exactly one call to McGenEventRegister
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
		call_expr = visitor.list_found_call[0] # We expect exactly one call to IoWMIRegistrationControl
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
			else:
				print(f"Could not find a assignment of '{WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME}.ControlGuid' in the function {idc.get_func_name(calling_function.start_ea)}.")
	else:
		print(f"Could not find 'WPP_MAIN_CB'.")

def rename_function_WppLoadTracingSupport():
	# Search the string "EtwRegisterClassicProvider"
	# Encode the string to UTF-16LE
	search_string_bytes = "EtwRegisterClassicProvider".encode('utf-16le')
	
	# Convert the byte string to a hex string for find_binary
	hex_pattern = "".join(f'{b:02X} ' for b in search_string_bytes)
	
	# Start searching from the beginning of the IDB.
	aEtwRegisterClassicProvider_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), hex_pattern, 16, ida_search.SEARCH_DOWN)
	if aEtwRegisterClassicProvider_address == idaapi.BADADDR:
		print(f"EtwRegisterClassicProvider not found.")
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
			print(f"Could not find {string_nth} memory assignment in the function {idc.get_func_name(function.start_ea)}.")
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
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memset_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function 'memset'.")
		return
	rename_function(function_address,'void *__fastcall memset(void *dest, int c, size_t count)', force=True)

def rename_function_memcmp():
	memset_size = 0x9C
	memset_patterns = [
	'04 2A ?? ?? 40 EA 01 03 13 F0 01 0F ?? ?? 13 F0 02 0F ?? ?? 12 1F ?? ?? 50 F8 04 3B'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memset_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function 'memcmp'.")
		return
	rename_function(function_address,'int __fastcall memcmp(const void *buffer1, const void *buffer2, size_t count)', force=True)

def rename_function_memmove():
	memmove_size = 0x10A
	memmove_patterns = [
	'43 1A 93 42 BF F4 DC AE 10 2A 91 F8 00 F0 70 D2 DF E8 02 F0 0A 08 0B 0E 13 16 1B 20'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memmove_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function 'memmove'.")
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
				print(f"Delete function at {hex(parent_function.start_ea)}.")
				ida_funcs.del_func(parent_function.start_ea)
		# Force disassembly of the bytes into instructions
		current_ea = function_address
		while current_ea < function_address+memmove_size:
			insn_len = idc.create_insn(current_ea)
			if insn_len <= 0:
				print(f"Failed to disassemble instruction at {hex(current_ea)}, maybe a 'jump table for switch statement' ?")
				break
			current_ea += insn_len
		# Add the function
		if not ida_funcs.add_func(function_address, function_address+memmove_size):
			print(f"Failed to create function 'memmove' at {hex(function_address)}!")
			return
	rename_function(function_address,'void *__fastcall memmove(void *dest, const void *src, size_t count)', force=True)
	
	memcpy_reverse_large_neon_address = idc.get_operand_value(function_address+0xFA, 0)
	if not ida_funcs.add_func(memcpy_reverse_large_neon_address, memcpy_reverse_large_neon_address+0x7C):
		print(f"Failed to create function '_memcpy_reverse_large_neon' at {hex(memcpy_reverse_large_neon_address)}!")
		return
	rename_function(memcpy_reverse_large_neon_address,'int __fastcall _memcpy_reverse_large_neon(int result, int a2, unsigned int a3)', force=True)
	
	memcpy_forward_new_patterns = [
	'91 F8 00 F0 10 2A 03 46 ?? ?? DF E8 02 F0 0A 08 0B 0E 13 16 1B 20 29 2E 37 40 4B 54'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memcpy_forward_new_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '__memcpy_forward_new'.")
		return
	rename_function(function_address,'int __fastcall _memcpy_forward_new(int result, unsigned int, int)', force=True)
	
	memcpy_forward_large_integer_patterns = [
	'5F EA C3 7C 2D E9 F0 4B 0D F1 18 0B ?? ?? 11 F8 01 4B 52 1E 03 F8 01 4B 5F EA C3 7C'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memcpy_forward_large_integer_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_memcpy_forward_large_integer'.")
		return
	rename_function(function_address,'void __fastcall _memcpy_forward_large_integer(int, char *, unsigned int, _BYTE *)', force=True)
	
	memcpy_forward_large_neon_patterns = [
	'2D E9 30 48 0D F1 08 0B 20 3A ?? ?? 20 3A 91 F8 20 F0 ?? ?? 91 F8 40 F0 20 3A 21 F9'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memcpy_forward_large_neon_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_memcpy_forward_large_neon'.")
		return
	rename_function(function_address,'void __fastcall _memcpy_forward_large_neon(int, __int64 *, unsigned int, int)', force=True)
	
	memcpy_decide_patterns = [
	'2D E9 30 48 0D F1 08 0B EF F3 00 84 14 F0 0F 04 ?? ?? 10 EE 10 4F C4 F3 07 65 24 09'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memcpy_decide_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_memcpy_decide'.")
		return
	rename_function(function_address,'int __fastcall _memcpy_decide()', force=True)
	
	memcpy_forward_large_func_address = ida_bytes.get_32bit(idc.get_operand_value(function_address+0x36, 1))
	rename_offset(memcpy_forward_large_func_address,'unsigned int _memcpy_forward_large_func')
	
	memcpy_reverse_large_func_address = ida_bytes.get_32bit(idc.get_operand_value(function_address+0x3C, 1))
	rename_offset(memcpy_reverse_large_func_address,'unsigned int _memcpy_reverse_large_func')
	
	memcpy_reverse_large_integer_patterns = [
	'83 18 89 18 5F EA C3 7C 11 F8 20 FC 2D E9 F0 4B 0D F1 18 0B ?? ?? 11 F8 01 4D 52 1E'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), memcpy_reverse_large_integer_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_memcpy_reverse_large_integer'.")
		return
	rename_function(function_address,'int __fastcall _memcpy_reverse_large_integer(int result, int, unsigned int)', force=True)


def rename_function_ppgsfailure():
	ppgsfailure_size = 0x14
	ppgsfailure_patterns = [
	'10 B5 6C 46 EC 46 2C F0 07 0C E5 46 ?? ?? ?? ?? A5 46 10 BD'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), ppgsfailure_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_ppgsfailure'.")
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
	'2D E9 00 48 EB 46 DB 69 1B 68 33 F0  03 02 50 58 13 F0 01 0F'
	]
	function_address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), GSHandlerCheck_patterns[0], 16, ida_search.SEARCH_DOWN)
	if function_address == idc.BADADDR:
		print(f"Cannot find function '_GSHandlerCheck'.")
		return
	rename_function(function_address,'int __fastcall _GSHandlerCheck(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord, _DISPATCHER_CONTEXT *DispatcherContext)', force=True)

def rename_function_jumps(imported_function_proto):
	imported_function_name = extract_function_name_from_proto(imported_function_proto)
	imported_function_address = get_imported_function_address(imported_function_name)
	if imported_function_address == idc.BADADDR:
		print("'{imported_function_name}' is not imported !")
		return
	
	code_xrefs = [
		xref for xref in idautils.XrefsTo(imported_function_address)
			if xref.type in [
				ida_xref.dr_R # keeps only Xrefs with type 'dr_R' (removes Xrefs with type 'dr_O' for example)
			]
	]
	xrefs_list = list(code_xrefs)  # Convert the generator to a list
	if len(xrefs_list) < 1:
		print("'{imported_function_name}' is never called !")
		return
	
	jump_function_proto = imported_function_proto.replace(imported_function_name, 'jump_'+imported_function_name)
	
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		if (function.end_ea - function.start_ea) == 0x0C:
			rename_function(function.start_ea, jump_function_proto) # add a suffix to the jump_function name if it already exists

def rename_function_WppTraceCallback():
	WppInitKm_address = idc.get_name_ea_simple('WppInitKm')
	if WppInitKm_address == idc.BADADDR:
		print("Cannot find function 'WppInitKm'.")
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
	else:
		print(f"Could not find a assignment of '{WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME}.Callback' in the function 'WppInitKm'.")
		return

def rename_functions_EventWrite():
	EtwWrite_address = get_imported_function_address('EtwWrite')
	if EtwWrite_address == idc.BADADDR:
		print("EtwWrite_address is not imported.")
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
		print("Cannot find pfnWppTraceMessage.")
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
		call_expr = visitor.list_found_call[0] # We expect exactly one call to pfnWppTraceMessage
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
	else:
		print(f"Could not find a assignment of '{structure_name}.{structure_member_name}' in the function {function_name}.")

def rename_callbacks_WdfDeviceInitSetPnpPowerEventCallbacks():
	wdf_function_address = find_wdf_function_address('WdfDeviceInitSetPnpPowerEventCallbacks')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(wdf_function_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		print("WdfDeviceInitSetPnpPowerEventCallbacks is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceInitSetPnpPowerEventCallbacks
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceInitSetPnpPowerEventCallbacks')
		visitor.apply_to(cfunc.body, None)
		call_expr = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceInitSetPnpPowerEventCallbacks
		
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
		print("WdfDeviceInitSetFileObjectConfig is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceInitSetFileObjectConfig
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceInitSetFileObjectConfig')
		visitor.apply_to(cfunc.body, None)
		call_expr = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceInitSetFileObjectConfig
		
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
		print("WdfDeviceCreate is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceCreate')
		visitor.apply_to(cfunc.body, None)
		call_expr = visitor.list_found_call[0] # We expect exactly one call to WdfDeviceCreate
		
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
		print("WdfIoQueueCreate is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfIoQueueCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfIoQueueCreate')
		visitor.apply_to(cfunc.body, None)
		for call_expr in visitor.list_found_call:
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
		print("WdfDeviceCreateDeviceInterface is never called.")
		return
	count = 0
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfIoQueueCreate
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceCreateDeviceInterface')
		visitor.apply_to(cfunc.body, None)
		for call_expr in visitor.list_found_call:
			if call_expr.a.size() < 3:
				print(f"In '{function_name}', the function 'WdfDeviceCreateDeviceInterface' does not have a 3rd parameter.")
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
		print("WdfDeviceAddQueryInterface is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfDeviceAddQueryInterface
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfDeviceAddQueryInterface')
		visitor.apply_to(cfunc.body, None)
		for call_expr in visitor.list_found_call:
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
			else:
				print(f"'{WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME}.InterfaceType' in the function {function_name} is not assigned to a memory object.")
		else:
			print(f"Could not find a assignment of '{WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME}.InterfaceType' in the function {function_name}.")
		
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
				print(f"'{WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME}.Interface' in the function {function_name} is not assigned to a stack frame variable.")
				return
		else:
			print(f"Could not find a assignment of '{WDF_QUERY_INTERFACE_CONFIG_STRUCT_NAME}.Interface' in the function {function_name}.")
			return
		
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
				print(f"'{variable_name}' in the function {function_name} is not assigned to a number.")
				return
		if interface_size ==0:
				print(f"Could not find a assignment of '{variable_name}' in the function {function_name} with a value > 0.")
				return

		# Create a new structure for the interface
		struc_id = idc.add_struc(-1, 'QUERY_INTERFACE', 0) # -1 adds it at the end, 0 means not a union
		if struc_id == idc.BADADDR:
			print(f"Failed to create structure 'QUERY_INTERFACE'!")
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
		
		frame_id = idc.get_frame_id(function.start_ea)
		#Delete existing members of the stack frame
		for i in range(interface_size-1):
			idc.del_struc_member(frame_id, variable_stack_frame_offset + i)
		result = idc.add_struc_member(frame_id, 'query_interface', variable_stack_frame_offset, idc.FF_STRUCT|idc.FF_DATA, struc_id, interface_size)
		if result != 0:
			print(f"Failed to apply structure QUERY_INTERFACE in the stack frame of the function '{function_name}' at the offset {hex(variable_stack_frame_offset)}! Error code : {result}")
			return
		print(f"Applyed structure QUERY_INTERFACE in the stack frame of the function '{function_name}' at the offset {hex(variable_stack_frame_offset)}.")
		
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
		print("WdfObjectGetTypedContextWorker is never called.")
		return
	for xref in xrefs_list:
		function = ida_funcs.get_func(xref.frm)
		function_name = idc.get_name(function.start_ea)
		# Decompile the function to find the call to WdfObjectGetTypedContextWorker
		cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_all_call_visitor('WdfObjectGetTypedContextWorker')
		visitor.apply_to(cfunc.body, None)
		for call_expr in visitor.list_found_call:
			if call_expr.a.size() < 3:
				print(f"In '{function_name}', the function 'WdfObjectGetTypedContextWorker' does not have a 3rd parameter.")
				continue
			param_expr = call_expr.a[2]
			if param_expr.op == idaapi.cot_ref: # pointer
				param_expr = param_expr.x
			if param_expr.op == idaapi.cot_obj:
				rename_wdf_context_type_info(param_expr.obj_ea)

def rename_functions_and_offsets():
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
				entry_function.start_ea == ida_search.find_binary(entry_function.start_ea, entry_function.end_ea, FxDriverEntry_patterns[0], 16, ida_search.SEARCH_DOWN) 
				or 
				entry_function.start_ea == ida_search.find_binary(entry_function.start_ea, entry_function.end_ea, FxDriverEntry_patterns[1], 16, ida_search.SEARCH_DOWN)
				):
				print(f"FxDriverEntry function found at {hex(entry_point_address)}.")
			else:
				print(f"FxDriverEntry function not found !")
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
	
	# Find the function calling 'WdfDriverCreate'
	# Usually, this is the 'DriverEntry' function
	WdfDriverCreate_address = find_wdf_function_address('WdfDriverCreate')
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(WdfDriverCreate_address)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	# Check if any references were found
	if len(xrefs_list) < 1:
		print("WdfDriverCreate is never called !")
		return
	if len(xrefs_list) > 1:
		print("WdfDriverCreate is called more than once !")
		return
	xref = xrefs_list[0]
	# Get the function object containing the target address
	function = ida_funcs.get_func(xref.frm)
	function_name = idc.get_func_name(function.start_ea)
	
	# Decompile the function to find the call to WdfDriverCreate
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_all_call_visitor('WdfDriverCreate')
	visitor.apply_to(cfunc.body, None)
	call_expr = visitor.list_found_call[0] # We expect exactly one call to WdfDriverCreate
	
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
	else:
		print(f"Could not find a assignment of '{WDF_OBJECT_ATTRIBUTES_STRUCT_NAME}.ContextTypeInfo' in the function {function_name}.")
	
	visitor = find_asg_type_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverDeviceAdd')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, 'NTSTATUS __fastcall EvtDriverDeviceAdd(WDFDRIVER *Driver, WDFDEVICE_INIT *DeviceInit)')
	else:
		print(f"Could not find a assignment of '{WDF_DRIVER_CONFIG_STRUCT_NAME}.EvtDriverDeviceAdd' in the function {function_name}.")
	
	visitor = find_asg_type_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverUnload')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if asg_expr:
		if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
			if asg_expr.y.x.op == idaapi.cot_obj:
				rename_function(asg_expr.y.x.obj_ea, 'void __fastcall EvtDriverUnload(WDFDRIVER *Driver)')
	else:
		print(f"Could not find a assignment of '{WDF_DRIVER_CONFIG_STRUCT_NAME}.EvtDriverUnload' in the function {function_name}.")
	
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