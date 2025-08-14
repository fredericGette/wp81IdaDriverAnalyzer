import ida_bytes
import idaapi
import idc
import ida_search
import ida_struct
import idautils
import ida_funcs
import ida_hexrays
import ida_frame
import ida_typeinf
import ida_ua
import ida_entry

"""
See https://github.com/VoidSec/DriverBuddyReloaded
Script to automatically identify WDF function pointers
Inspired by http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html
Originally by Nicolas Guigo
Modified by Braden Hollembaek, Adam Pond and Paolo Stagno
"""

MAJOR_VERSION_OFFSET = 0x0
MINOR_VERSION_OFFSET = 0x4

WDF_FUNCTIONS_OFFSET = 0x10

WDFFUNCTIONS_STRUCT_NAME = "WDFFUNCTIONS"
WDF_DRIVER_CONFIG_STRUCT_NAME = "_WDF_DRIVER_CONFIG"

PTR_SIZE = 4

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
WdfFunctions_address = 0

def add_WDFFUNCTIONS_structure():
	global WdfFunctions_address
	# Search the KmdfLibrary
	
	# Encode the string to UTF-16LE
	search_string_bytes = "KmdfLibrary".encode('utf-16le')
	
	# Convert the byte string to a hex string for find_binary
	hex_pattern = "".join(f'{b:02X} ' for b in search_string_bytes)
	
	# Start searching from the beginning of the IDB.
	address = ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA), idc.get_inf_attr(idc.INF_MAX_EA), hex_pattern, 16, ida_search.SEARCH_DOWN)
	if address == idaapi.BADADDR:
		print(f"KmdfLibrary not found !")
		return
		
	ref_to_address = idc.get_first_dref_to(address)
	
	# The name of the library is referenced in this structure:
	#WdfBindInfo	DCD 0x20				; Size
	#				DCD aKmdflibrary		; Component ; "KmdfLibrary"
	#				DCD 1					; Version.Major
	#				DCD 0xB					; Version.Minor
	#				DCD 0					; Version.Build
	#				DCD 0x1B0				; FuncCount
	#				DCD WdfFunctions		; FuncTable
	#				DCD 0					; Module
	
	major = idc.get_wide_dword(ref_to_address + PTR_SIZE + MAJOR_VERSION_OFFSET)
	minor = idc.get_wide_dword(ref_to_address + PTR_SIZE + MINOR_VERSION_OFFSET)
	print(f"Found KmdfLibrary version {major}.{minor}")
	if (major!=1 or minor !=11):
		print(f"Only version 1.11 is supported by this plugin !")
		return
	
	idc.set_name(ref_to_address-4, 'WdfBindInfo')
	
	structure_id = -1
	# check if the structure already exists
	structure_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
	if structure_id != -1:
		# delete old structure
		idc.del_struc(structure_id)
	idc.add_struc(-1, WDFFUNCTIONS_STRUCT_NAME, 0)
	structure_id = ida_struct.get_struc_id(WDFFUNCTIONS_STRUCT_NAME)
	for func_name in kmdf1_11:
		idc.add_struc_member(structure_id, func_name, idc.BADADDR, idc.FF_DATA | ida_bytes.FF_DWORD, -1, PTR_SIZE)
	WdfFunctions_address = idaapi.get_32bit(ref_to_address + PTR_SIZE + WDF_FUNCTIONS_OFFSET)
	size = idc.get_struc_size(structure_id)
	# Set a name to the memory address
	idc.set_name(WdfFunctions_address, 'WdfFunctions')
	# Apply the structure to the memory address
	ida_bytes.create_struct(WdfFunctions_address, size, structure_id, True)
	print(f"Applyed structure {WDFFUNCTIONS_STRUCT_NAME} (size={hex(size)}) at {hex(WdfFunctions_address)}")

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

def find_wdf_functions():
	address_WdfDriverCreate = find_wdf_function_address('WdfDriverCreate')
	print(f"Address of WdfDriverCreate: {hex(address_WdfDriverCreate)}")
	
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(address_WdfDriverCreate)
	
	# Check if any references were found
	if not xrefs:
		print("No cross-references found.")
	else:
		for xref in xrefs:
			print(f"  - Reference from: {hex(xref.frm)}")
			# Get the function object containing the target address
			function = ida_funcs.get_func(xref.frm)
			function_address = function.start_ea
			function_name = idc.get_func_name(function_address)
			print(f"  - Function name: {function_name}")

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

def create_unicode_string():
	"""
	Creates the _UNICODE_STRING structure in the current IDB.
	"""
	struct_name = "_UNICODE_STRING"
	
	# Check if the structure already exists
	struct_id = idc.get_struc_id(struct_name)
	if struct_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struct_id)
	
	# Create a new structure with the specified name.
	struct_id = idc.add_struc(-1, struct_name, 0)
	if struct_id == idc.BADADDR:
		print(f"Failed to create structure '{struct_name}'.")
		return
	
	# Add the 'Length' member (2 bytes, WORD).
	# idc.add_struc_member(struct_id, member_name, offset, flags, type_id, size)
	idc.add_struc_member(struct_id, "Length", 0x0, idc.FF_WORD, -1, 2)
	
	# Add the 'MaximumLength' member (2 bytes, WORD).
	idc.add_struc_member(struct_id, "MaximumLength", 0x2, idc.FF_WORD, -1, 2)
	
	# Add the 'Buffer' member (4 bytes, DWORD, pointer).
	# Since it's a pointer, we use FF_DWORD for the 4-byte size.
	idc.add_struc_member(struct_id, "Buffer", 0x4, idc.FF_DWORD, -1, 4)

def create_driver_object_struct():
	"""
	Creates the _DRIVER_OBJECT structure with its members.
	"""
	struct_name = "_DRIVER_OBJECT"
	
	# Check if the structure already exists
	struc_id = idc.get_struc_id(struct_name)
	if struc_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struc_id)
	
	# Create the structure
	struc_id = idc.add_struc(-1, struct_name, 0)
	if struc_id == idc.BADADDR:
		print(f"Failed to create structure '{struct_name}'.")
		return
	
	# Add members to the structure
	idc.add_struc_member(struc_id, "Type", 0x0, idc.FF_WORD, -1, 2)
	idc.add_struc_member(struc_id, "Size", 0x2, idc.FF_WORD, -1, 2)
	idc.add_struc_member(struc_id, "DeviceObject", 0x4, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "Flags", 0x8, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverStart", 0xC, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverSize", 0x10, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverSection", 0x14, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverExtension", 0x18, idc.FF_DWORD, -1, 4)
	
	# Add the _UNICODE_STRING member
	unicode_string_id = idc.get_struc_id("_UNICODE_STRING")
	if unicode_string_id == idc.BADADDR:
		print("Structure '_UNICODE_STRING' is missing !")
		return
		
	# Add _UNICODE_STRING as a member
	idc.add_struc_member(struc_id, "DriverName", 0x1C, idc.FF_STRUCT, unicode_string_id, idc.get_struc_size(unicode_string_id))
	
	idc.add_struc_member(struc_id, "HardwareDatabase", 0x24, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "FastIoDispatch", 0x28, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverInit", 0x2C, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverStartIo", 0x30, idc.FF_DWORD, -1, 4)
	idc.add_struc_member(struc_id, "DriverUnload", 0x34, idc.FF_DWORD, -1, 4)
	
	# Add the MajorFunction array
	# The flag FF_DWORD|FF_DATA is used for a DCD type
	idc.add_struc_member(struc_id, "MajorFunction", 0x38, idc.FF_DWORD | idc.FF_DATA, -1, 28*4)


def create_wdf_driver_config_struc():
	"""
	Creates the _WDF_DRIVER_CONFIG structure with all its members.
	"""
	# Define the structure name and the member information
	struc_name = WDF_DRIVER_CONFIG_STRUCT_NAME
	members = [
		("Size", 0x00, idc.FF_DWORD, 4),
		("EvtDriverDeviceAdd", 0x04, idc.FF_DWORD, 4),
		("EvtDriverUnload", 0x08, idc.FF_DWORD, 4),
		("DriverInitFlags", 0x0C, idc.FF_DWORD, 4),
		("DriverPoolTag", 0x10, idc.FF_DWORD, 4),
	]
	
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
	for name, offset, flag, size in members:
		# The add_struc_member function requires the structure ID,
		# member name, offset, flags, and size.
		result = idc.add_struc_member(
			struc_id,		# Structure ID
			name,			# Member name
			offset,			# Member offset
			flag,			# Flags (e.g., idc.FF_DWORD for a 4-byte DCD)
			-1,				# Type ID (use -1 for simple types like DWORD)
			size			# Size of the member
		)

def create_WDFDRIVER():
	"""
	Creates the WDFDRIVER__ structure in the current IDB.
	"""
	struct_name = "WDFDRIVER__"
	
	# Check if the structure already exists
	struct_id = idc.get_struc_id(struct_name)
	if struct_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struct_id)
	
	# Create a new structure with the specified name.
	struct_id = idc.add_struc(-1, struct_name, 0)
	if struct_id == idc.BADADDR:
		print(f"Failed to create structure '{struct_name}'.")
		return
	
	# Add the 'unused' member (4 bytes, DWORD).
	idc.add_struc_member(struct_id, "unused", 0x4, idc.FF_DWORD, -1, 4)

def create_WDFDEVICE_INIT():
	"""
	Creates the WDFDEVICE_INIT structure in the current IDB.
	"""
	struct_name = "WDFDEVICE_INIT"
	
	# Check if the structure already exists
	struct_id = idc.get_struc_id(struct_name)
	if struct_id != idc.BADADDR:
		# delete old structure
		idc.del_struc(struct_id)
	
	# Create a new structure with the specified name.
	struct_id = idc.add_struc(-1, struct_name, 0)
	if struct_id == idc.BADADDR:
		print(f"Failed to create structure '{struct_name}'.")
		return
	
	# Add the 'unused' member (4 bytes, DWORD).
	idc.add_struc_member(struct_id, "unused", 0x4, idc.FF_DWORD, -1, 4)

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

def add_parameters_structures():
	create_unicode_string()
	create_driver_object_struct()
	create_wdf_driver_config_struc()
	create_WDFDRIVER()
	create_WDFDEVICE_INIT()

def rename_wdf_functions():
	
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
	destination_address = idc.get_operand_value(entry_point_address+12, 0)
	idc.set_name(destination_address, '__security_init_cookie')
	destination_address = idc.get_operand_value(entry_point_address+20, 0)
	rename_function(destination_address, 'int __fastcall FxDriverEntryWorker(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)')
	
	# Get the address of the function by its name
	function_address = idc.get_name_ea_simple('FxDriverEntryWorker')
	destination_address = idc.get_operand_value(function_address+16, 0)
	rename_function(destination_address, 'int __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)')
	
	address_WdfDriverCreate = find_wdf_function_address('WdfDriverCreate')
	
	# Use XrefsTo to get all cross-references to the target address
	xrefs = idautils.XrefsTo(address_WdfDriverCreate)
	
	# Check if any references were found
	if not xrefs:
		print("WdfDriverCreate is never called !")
		return
	
	# Iterate through the references and print the source address
	xrefs_list = list(xrefs)  # Convert the generator to a list
	xrefs_list_size = len(xrefs_list)
	for xref in xrefs_list:
		# Get the function object containing the target address
		function = ida_funcs.get_func(xref.frm)
		function_address = function.start_ea
		function_name = idc.get_func_name(function_address)
		
		# Decompile the function to find the call to WdfDriverCreate
		cfunc = ida_hexrays.decompile(function)
		# Iterate through the C-tree to find the call to WdfDriverCreate
		class find_call_visitor(idaapi.ctree_visitor_t):
			def __init__(self, search_function_name):
				idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
				self.found_call = None
				self.search_function_name = search_function_name

			def visit_expr(self, expr):
				if expr.op == idaapi.cot_call:
					if expr.x.op  == idaapi.cot_cast:
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
				return 0  # Continue traversal
		
		visitor = find_call_visitor('WdfDriverCreate')
		visitor.apply_to(cfunc.body, None)
		
		call_expr = visitor.found_call
		if not call_expr:
			print(f"Could not find a call to 'WdfFunctions.WdfDriverCreate' in the function {function_name}.")
			return
		
		# Access the 5th parameter (DriverConfig) and change its type
		# Parameters are stored in the `a` field (array of expressions)
		if call_expr.a.size() < 5:
			print("The function call does not have a 5th parameter.")
			return
		
		# The 5th parameter is at index 4 (0-based index)
		param5_expr = call_expr.a[4]
		
		if not param5_expr.v.getv().is_stk_var():
			print("The 5th parameter of WdfDriverCreate ({param4_expr.v.getv().name}) is not a stack frame variable !")
			return
		
		struc_id = ida_struct.get_struc_id(WDF_DRIVER_CONFIG_STRUCT_NAME)
		s = ida_struct.get_struc(struc_id)
		struc_size = ida_struct.get_struc_size(s)
		
		frame_id = idc.get_frame_id(function.start_ea)
		stack_frame_offset = param5_expr.v.getv().get_stkoff()
		
		#Delete existing member of the stack frame
		for i in range(struc_size-1):
			idc.del_struc_member(frame_id, stack_frame_offset + i)
		
		result = idc.add_struc_member(frame_id, "DriverConfig",stack_frame_offset, idc.FF_STRUCT|idc.FF_DATA, struc_id, struc_size)
		if result != 0:
			print(f"Failed to apply structure {WDF_DRIVER_CONFIG_STRUCT_NAME} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}. Error code : {result}")
			return
		print(f"Applyed structure {WDF_DRIVER_CONFIG_STRUCT_NAME} in the stack frame of the function '{function_name}' at the offset {hex(stack_frame_offset)}")
		
		# Invalidate the decompilation cache and close all related pseudocode windows.
		ida_hexrays.mark_cfunc_dirty(function.start_ea, True)
		
		# Decompile again the function to find the assignment of DriverConfig
		cfunc = ida_hexrays.decompile(function)
		# Iterate through the C-tree to find the assignment of DriverConfig
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
