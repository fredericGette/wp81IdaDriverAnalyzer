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
WDFDRIVER_STRUCT_NAME = "WDFDRIVER__"
WDFDEVICE_INIT_STRUCT_NAME = "WDFDEVICE_INIT"
WDF_OBJECT_ATTRIBUTES_STRUCT_NAME = "_WDF_OBJECT_ATTRIBUTES"
WDF_OBJECT_CONTEXT_TYPE_INFO_STRUCT_NAME = "_WDF_OBJECT_CONTEXT_TYPE_INFO"
EVENT_FILTER_DESCRIPTOR_STRUCT_NAME = "_EVENT_FILTER_DESCRIPTOR"
WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME = "_WPP_TRACE_CONTROL_BLOCK"
DEVICE_OBJECT_STRUCT_NAME = "_DEVICE_OBJECT"
WDF_BIND_INFO_STRUCT_NAME = "_WDF_BIND_INFO"


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
		print(f"Failed to create structure '{struc_name}'")
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
	if idc.set_local_type(-1,"typedef unsigned __int16 wchar_t;", idc.PT_SIL) == 0:
		print("Error when adding local type 'wchar_t'.")

def rename_function(function_address, new_proto):
	old_name = idc.get_name(function_address)
	
	# Split the string by spaces and get the third element
	parts = new_proto.split(' ')
	function_name_with_paren = parts[2]
	# Remove the opening parenthesis
	new_function_name = function_name_with_paren.split('(')[0]
	
	idc.set_name(function_address, new_function_name)
	idc.SetType(function_address, new_proto)
	print(f"Renamed '{old_name}' to '{new_proto}'")


# Iterate through a C-tree to find the call to a WDF function
# The memory address of the WDF function is casted in order to be called
# example: ((int (__fastcall *)(int, int, int, int *, _WDF_DRIVER_CONFIG *, _DWORD))WdfFunctions.WdfDriverCreate)(...)
class find_call_visitor(idaapi.ctree_visitor_t):
	def __init__(self, search_function_name):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
		self.found_call = None
		self.search_function_name = search_function_name

	def visit_expr(self, expr):
		if expr.op == idaapi.cot_call:
			if expr.x.op  == idaapi.cot_cast: # Case of a call to a WDF function
				if expr.x.x.op == idaapi.cot_memref:
					if expr.x.x.x.op == idaapi.cot_obj:
						object_name = idc.get_name(expr.x.x.x.obj_ea)
						member_offset = expr.x.x.m
						if object_name == 'WdfFunctions':
							struc_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
							struc_t = ida_struct.get_struc (struc_id)
							member_id = ida_struct.get_member_id(struc_t, member_offset)
							member_name = ida_struct.get_member_name(member_id)
							if member_name == self.search_function_name:
								self.found_call = expr
								return 1  # Stop traversal
			elif expr.x.op  == idaapi.cot_obj: # Case of a call to an imported function or to another function of the driver
				object_name = idc.get_name(expr.x.obj_ea)
				if object_name == self.search_function_name:
					self.found_call = expr
					return 1  # Stop traversal
		return 0  # Continue traversal

# Iterate through a C-tree to find the assignment of a variable of a given type
class find_asg_visitor(idaapi.ctree_visitor_t):
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
						struc_id = ida_struct.get_struc_id(self.search_var_type)
						struc_t = ida_struct.get_struc (struc_id)
						member_id = ida_struct.get_member_id(struc_t, member_offset)
						member_name = ida_struct.get_member_name(member_id)
						if member_name == self.search_var_type_member:
							self.found_asg = expr
							return 1  # Stop traversal
		return 0  # Continue traversal

def apply_structure_to_stack_parameter(function_address, call_expr, idx_param, struct_name, new_var_name):
	
	function_name = idc.get_func_name(function_address)
	
	if call_expr.a.size() < idx_param+1: #(+1 because 0-based index
		print("The function call does not have a {idx_param+1}th parameter.")
		return
	param_expr = call_expr.a[idx_param]
	if not param_expr.v.getv().is_stk_var():
		print(f"The {idx_param+1}th parameter ({param_expr.v.getv().name}) is not a stack frame variable !")
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
		print(f"Failed to apply structure {struct_name} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}. Error code : {result}")
		return
	print(f"Applyed structure {struct_name} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}")

def rename_offset(offset_address, new_definition):
	old_name = idc.get_name(offset_address)
	
	matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', new_definition)
	if matches:
		new_name = matches[-1] # get the last match of the capturing group
	else:
		print(f"No match found in {new_definition} for offset {hex(offset_address)}")
		return
	
	idc.set_name(offset_address, new_name)
	if new_name != new_definition: # there's some type definition in addition to the name.
		idc.SetType(offset_address, new_definition)
	print(f"Renamed '{old_name}' to '{new_definition}'")

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
		print(f"Failed to apply structure {struct_name} at the offset {hex(offset_address)}.")
		return
	print(f"Applyed structure {struct_name} at the offset {hex(offset_address)}")

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
		print(f"Failed to create structure '{context_name}'")
		return
	for idx in range(context_size):
		idc.add_struc_member(struc_id, f"field_{idx:x}", idx, idc.FF_BYTE | idc.FF_DATA, -1,1)

def get_imported_function_address(func_name):
	for name_ea, name in idautils.Names():
		if name == func_name:
			return name_ea

def rename_function_McGenEventRegister():
	EtwRegister_address = get_imported_function_address('EtwRegister')
	if EtwRegister_address == idc.BADADDR:
		print("EtwRegister is not imported !")
		return
	rename_function(EtwRegister_address, 'int __fastcall EtwRegister(const _GUID *ProviderId, void (__fastcall *EnableCallback)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *CallbackContext), void *CallbackContext, unsigned __int64 *RegHandle)')
	xrefs = idautils.XrefsTo(EtwRegister_address)
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
	rename_function(McGenEventRegister_function.start_ea, 'int __fastcall McGenEventRegister(const _GUID *ProviderId, void (__fastcall *EnableCallback)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *), void *CallbackContext, unsigned __int64 *RegHandle)')
	# Decompile the function McGenEventRegister to find the call to EtwRegister
	cfunc = ida_hexrays.decompile(McGenEventRegister_function,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_call_visitor('EtwRegister')
	visitor.apply_to(cfunc.body, None)
	call_expr = visitor.found_call
	if not call_expr:
		print(f"Could not find a call to 'EtwRegister' in the function McGenEventRegister.")
		return
	if call_expr.a.size() < 2: 
		print("The function call does not have a 2nd parameter.")
		return
	param_expr = call_expr.a[1] # Because 0-based index
	if param_expr.op == idaapi.cot_cast and param_expr.x.op == idaapi.cot_obj:
		rename_function(param_expr.x.obj_ea, 'void __fastcall ETW_EnableCallback(const _GUID *SourceId, unsigned int ControlCode, unsigned __int8 Level, unsigned __int64 MatchAnyKeyword, unsigned __int64 MatchAllKeyword, _EVENT_FILTER_DESCRIPTOR *FilterData, void *CallbackContext)')
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(McGenEventRegister_function.start_ea, True)
	
	xrefs = idautils.XrefsTo(McGenEventRegister_function.start_ea)
	xrefs_list = list(xrefs)  # Convert the generator to a list
	count = 0
	for xref in xrefs_list:
		count += 1
		# Get the function object containing the target address
		calling_function = ida_funcs.get_func(xref.frm)
		# Decompile the calling function to find the call to McGenEventRegister
		cfunc = ida_hexrays.decompile(calling_function,None,ida_hexrays.DECOMP_NO_WAIT)
		visitor = find_call_visitor('McGenEventRegister')
		visitor.apply_to(cfunc.body, None)
		call_expr = visitor.found_call
		if not call_expr:
			print(f"Could not find a call to 'McGenEventRegister' in the function {idc.get_name(calling_function.start_ea)}.")
			continue
		if call_expr.a.size() < 4: 
			print("The function call does not have 4 parameters.")
			continue
		ProviderId_param_expr = call_expr.a[0]
		if ProviderId_param_expr.op == idaapi.cot_ref and ProviderId_param_expr.x.op == idaapi.cot_obj:
			rename_offset(ProviderId_param_expr.x.obj_ea, f'_GUID ETW_Provider_GUID_{count}')
		CallbackContext_param_expr = call_expr.a[2]
		if CallbackContext_param_expr.op == idaapi.cot_ref and CallbackContext_param_expr.x.op == idaapi.cot_obj:
			rename_offset(CallbackContext_param_expr.x.obj_ea, f'void *ETW_CallbackContext_{count}')
		RegHandle_param_expr = call_expr.a[3]
		if RegHandle_param_expr.op == idaapi.cot_cast and RegHandle_param_expr.x.op == idaapi.cot_ref and RegHandle_param_expr.x.x.op == idaapi.cot_obj:
			rename_offset(RegHandle_param_expr.x.x.obj_ea, f'unsigned __int64 ETW_RegistrationHandle_{count}')

def rename_function_WppInitKm():
	IoWMIRegistrationControl_address = get_imported_function_address('IoWMIRegistrationControl')
	if IoWMIRegistrationControl_address == idc.BADADDR:
		print("IoWMIRegistrationControl is not imported !")
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
		visitor = find_call_visitor('IoWMIRegistrationControl')
		visitor.apply_to(cfunc.body, None)
		call_expr = visitor.found_call
		if not call_expr:
			print(f"Could not find a call to 'IoWMIRegistrationControl' in the function {idc.get_name(calling_function.start_ea)}.")
			continue
		if call_expr.a.size() < 2: 
			print("The function call does not have 2 parameters.")
			continue
		param1_expr = call_expr.a[0]
		param2_expr = call_expr.a[1]
		if param2_expr.op == idaapi.cot_num and param2_expr.numval() & 1 == 1 : # WMIREG_ACTION_REGISTER
			if param1_expr.op == idaapi.cot_ref and param1_expr.x.op == idaapi.cot_obj:
				apply_structure_to_offset(param1_expr.x.obj_ea, WPP_TRACE_CONTROL_BLOCK_STRUCT_NAME) # In reality, it's an union named "WPP_PROJECT_CONTROL_BLOCK" witch contains the structure "_WPP_TRACE_CONTROL_BLOCK"
				rename_offset(param1_expr.x.obj_ea, f'_WPP_TRACE_CONTROL_BLOCK WPP_MAIN_CB')
				rename_function(calling_function.start_ea, 'void __fastcall WppInitKm(_DEVICE_OBJECT *DevObject, const _UNICODE_STRING *RegPath)')
				WPP_GLOBAL_Control_address = idc.get_operand_value(calling_function.start_ea+8, 1) # second operand (operand 1)
				rename_offset(WPP_GLOBAL_Control_address, '_WPP_TRACE_CONTROL_BLOCK *WPP_GLOBAL_Control') # In reality, it's an union named "WPP_PROJECT_CONTROL_BLOCK" witch contains the structure "_WPP_TRACE_CONTROL_BLOCK"
	# Clear the decompilation caches to force the usage of the type _WPP_TRACE_CONTROL_BLOCK
	ida_hexrays.clear_cached_cfuncs()

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
				print(f"FxDriverEntry function found at {hex(entry_point_address)}")
			else:
				print(f"FxDriverEntry function not found !")
				return
	
	rename_function(entry_point_address, 'int __fastcall FxDriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)')
	
	# Get the destination address of the first operand (operand 0)
	# of the instruction at bl_instruction_address.
	security_init_cookie_address = idc.get_operand_value(entry_point_address+12, 0)
	rename_offset(security_init_cookie_address, 'unsigned int __security_init_cookie')
	FxDriverEntryWorker_address = idc.get_operand_value(entry_point_address+20, 0)
	rename_function(FxDriverEntryWorker_address, 'int __fastcall FxDriverEntryWorker(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)')
	
	# Get the address of the function by its name
	function_address = idc.get_name_ea_simple('FxDriverEntryWorker')
	DriverEntry_address = idc.get_operand_value(function_address+16, 0)
	rename_function(DriverEntry_address, 'int __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)')
	print(f"function_address+0x26 = {hex(function_address+0x26)}")
	WdfDriverStubRegistryPathBuffer_address = ida_bytes.get_32bit(idc.get_operand_value(function_address+0x26, 1))
	print(f"WdfDriverStubRegistryPathBuffer_address = {hex(WdfDriverStubRegistryPathBuffer_address)}")

	rename_offset(WdfDriverStubRegistryPathBuffer_address, 'wchar_t WdfDriverStubRegistryPathBuffer[260]')
	
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
	function_address = function.start_ea
	function_name = idc.get_func_name(function_address)
	
	# Decompile the function to find the call to WdfDriverCreate
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	visitor = find_call_visitor('WdfDriverCreate')
	visitor.apply_to(cfunc.body, None)
	call_expr = visitor.found_call
	if not call_expr:
		print(f"Could not find a call to 'WdfFunctions.WdfDriverCreate' in the function {function_name}.")
		return
	
	# Access the 3th parameter (DriverAttributes) and change its type.
	apply_structure_to_stack_parameter(function_address, call_expr, 3, WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, "DriverAttributes")
	
	# Access the 4th parameter (DriverConfig) and change its type.
	apply_structure_to_stack_parameter(function_address, call_expr, 4, WDF_DRIVER_CONFIG_STRUCT_NAME, "DriverConfig")
	
	# Invalidate the decompilation cache and close all related pseudocode windows.
	ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
	
	# Decompile again the function to find the assignments of DriverAttributes and DriverConfig
	cfunc = ida_hexrays.decompile(function,None,ida_hexrays.DECOMP_NO_WAIT)
	
	visitor = find_asg_visitor(WDF_OBJECT_ATTRIBUTES_STRUCT_NAME, 'ContextTypeInfo')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if not asg_expr:
		print(f"Could not find a assignment of '{WDF_OBJECT_ATTRIBUTES_STRUCT_NAME}.ContextTypeInfo' in the function {function_name}.")
		return
	if asg_expr.y.op == idaapi.cot_cast: # there is a cast from void* to int
		if asg_expr.y.x.op == idaapi.cot_obj:
			rename_wdf_context_type_info(asg_expr.y.x.obj_ea)
	
	visitor = find_asg_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverDeviceAdd')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if not asg_expr:
		print(f"Could not find a assignment of '{WDF_DRIVER_CONFIG_STRUCT_NAME}.EvtDriverDeviceAdd' in the function {function_name}.")
		return
	if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
		if asg_expr.y.x.op == idaapi.cot_obj:
			rename_function(asg_expr.y.x.obj_ea, 'int __fastcall EvtDriverDeviceAdd(WDFDRIVER__ *Driver, WDFDEVICE_INIT *DeviceInit)')
	visitor = find_asg_visitor(WDF_DRIVER_CONFIG_STRUCT_NAME, 'EvtDriverUnload')
	visitor.apply_to(cfunc.body, None)
	asg_expr = visitor.found_asg
	if not asg_expr:
		print(f"Could not find a assignment of '{WDF_DRIVER_CONFIG_STRUCT_NAME}.EvtDriverUnload' in the function {function_name}.")
		return
	if asg_expr.y.op == idaapi.cot_cast: # there is a cast from int() to int
		if asg_expr.y.x.op == idaapi.cot_obj:
			rename_function(asg_expr.y.x.obj_ea, 'int __fastcall EvtDriverUnload(WDFDRIVER__ *Driver)')
	
	rename_function_McGenEventRegister()
	rename_function_WppInitKm()
