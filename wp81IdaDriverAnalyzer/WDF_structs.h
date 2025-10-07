// See https://learn.microsoft.com/
// See https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
// See https://github.com/IOActive/kmdf_re/blob/master/code/WDFStructs.h

typedef unsigned __int16 wchar_t;
typedef wchar_t *PWSTR;
typedef unsigned int size_t;
typedef unsigned char BYTE;
typedef unsigned int ULONG;
typedef long LONG;
typedef unsigned long DWORD;
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONGLONG;
typedef unsigned short USHORT;
typedef short SHORT;
typedef void VOID;
typedef void *PVOID;
typedef void *HANDLE;
typedef BYTE BOOLEAN;
typedef unsigned char UCHAR;
typedef char CHAR;
typedef CHAR *PCHAR;
typedef int NTSTATUS;
typedef HANDLE WDFCMRESLIST;
typedef HANDLE WDFCOLLECTION;
typedef HANDLE WDFDEVICE;
typedef HANDLE WDFDEVICE_INIT;
typedef HANDLE WDFDRIVER;
typedef HANDLE WDFFILEOBJECT;
typedef HANDLE WDFINTERRUPT;
typedef HANDLE WDFIOTARGET;
typedef HANDLE WDFLOOKASIDE;
typedef HANDLE WDFMEMORY;
typedef HANDLE WDFOBJECT;
typedef HANDLE WDFQUEUE;
typedef HANDLE WDFREQUEST;
typedef HANDLE WDFSPINLOCK;
typedef HANDLE WDFWAITLOCK;
typedef HANDLE WDFWORKITEM;
typedef ULONG KSPIN_LOCK;
typedef UCHAR KIRQL;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct _DRIVER_OBJECT { // Will be redefined later
    int temporary_structure;
};

struct _DEVICE_OBJECT { // Will be redefined later
    int temporary_structure;
};

struct _DRIVER_EXTENSION {
    _DRIVER_OBJECT *DriverObject;
    int (__fastcall *AddDevice)(_DRIVER_OBJECT *, _DEVICE_OBJECT *);
    unsigned int Count;
    _UNICODE_STRING ServiceKeyName;
};

struct _VPB {
    __int16 Type;
    __int16 Size;
    unsigned __int16 Flags;
    unsigned __int16 VolumeLabelLength;
    _DRIVER_OBJECT *DeviceObject;
    _DRIVER_OBJECT *RealDevice;
    unsigned int SerialNumber;
    unsigned int ReferenceCount;
    wchar_t VolumeLabel[32];
};

struct _SECTION_OBJECT_POINTERS {
    void *DataSectionObject;
    void *SharedCacheMap;
    void *ImageSectionObject;
};

struct _KEVENT {
    __int8 Header[0x10]; // structure _DISPATCHER_HEADER
};

struct _IO_COMPLETION_CONTEXT {
    void *Port;
    void *Key;
};

struct _LIST_ENTRY {
    _LIST_ENTRY *Flink;
    _LIST_ENTRY *Blink;
};

struct _FILE_OBJECT {
    __int16 Type;
    __int16 Size;
    _DEVICE_OBJECT *DeviceObject;
    _VPB *Vpb;
    void *FsContext;
    void *FsContext2;
    _SECTION_OBJECT_POINTERS *SectionObjectPointer;
    void *PrivateCacheMap;
    int FinalStatus;
    _FILE_OBJECT *RelatedFileObject;
    unsigned __int8 LockOperation;
    unsigned __int8 DeletePending;
    unsigned __int8 ReadAccess;
    unsigned __int8 WriteAccess;
    unsigned __int8 DeleteAccess;
    unsigned __int8 SharedRead;
    unsigned __int8 SharedWrite;
    unsigned __int8 SharedDelete;
    unsigned int Flags;
    _UNICODE_STRING FileName;
    LONGLONG CurrentByteOffset;
    unsigned int Waiters;
    unsigned int Busy;
    void *LastLock;
    _KEVENT Lock;
    _KEVENT Event;
    _IO_COMPLETION_CONTEXT *CompletionContext;
    unsigned int IrpListLock;
    _LIST_ENTRY IrpList;
    void *FileObjectExtension;
};

struct _MDL
{
    _MDL *Next;
    __int16 Size;
    __int16 MdlFlags;
    struct _EPROCESS *Process;
    void *MappedSystemVa;
    void *StartVa;
    unsigned int ByteCount;
    unsigned int ByteOffset;
};

struct _IO_STATUS_BLOCK {
    union {
        int Status;
        void *Pointer;
    } ___u0;
    unsigned int Information;
};

struct _IRP {
    __int16 Type;
    unsigned __int16 Size;
    _MDL *MdlAddress;
    unsigned int Flags;
    union {
        void *MasterIrp;
        int IrpCount;
        void *SystemBuffer;
    } AssociatedIrp;
    _LIST_ENTRY ThreadListEntry;
    _IO_STATUS_BLOCK IoStatus;
    char RequestorMode;
    unsigned __int8 PendingReturned;
    char StackCount;
    char CurrentLocation;
    unsigned __int8 Cancel;
    unsigned __int8 CancelIrql;
    char ApcEnvironment;
    unsigned __int8 AllocationFlags;
    _IO_STATUS_BLOCK *UserIosb;
    _KEVENT *UserEvent;
    __int8 Overlay[0x08]; // TODO
    void (__fastcall *CancelRoutine)(_DEVICE_OBJECT *, _IRP *);
    void *UserBuffer;
    __int8 Tail[0x30]; // TODO
};

typedef _IRP *PIRP;

struct __declspec(align(8)) _FILE_BASIC_INFORMATION {
    LONGLONG CreationTime;
    LONGLONG LastAccessTime;
    LONGLONG LastWriteTime;
    LONGLONG ChangeTime;
    unsigned int FileAttributes;
    // padding byte
    // padding byte
    // padding byte
    // padding byte
};

struct __declspec(align(4)) _FILE_STANDARD_INFORMATION {
    LONGLONG AllocationSize;
    LONGLONG EndOfFile;
    unsigned int NumberOfLinks;
    unsigned __int8 DeletePending;
    unsigned __int8 Directory;
    // padding byte
    // padding byte
};

struct __declspec(align(8)) _FILE_NETWORK_OPEN_INFORMATION // sizeof=0x38
{
    LONGLONG CreationTime;
    LONGLONG LastAccessTime;
    LONGLONG LastWriteTime;
    LONGLONG ChangeTime;
    LONGLONG AllocationSize;
    LONGLONG EndOfFile;
    unsigned int FileAttributes;
    // padding byte
    // padding byte
    // padding byte
    // padding byte
};

struct _ERESOURCE {
    __int8 toDo[0x38];
};

struct _FAST_IO_DISPATCH {
    unsigned int SizeOfFastIoDispatch;
    unsigned __int8 (__fastcall *FastIoCheckIfPossible)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned __int8, unsigned int, unsigned __int8, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoRead)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned __int8, unsigned int, void *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoWrite)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned __int8, unsigned int, void *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoQueryBasicInfo)(_FILE_OBJECT *, unsigned __int8, _FILE_BASIC_INFORMATION *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoQueryStandardInfo)(_FILE_OBJECT *, unsigned __int8, _FILE_STANDARD_INFORMATION *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoLock)(_FILE_OBJECT *, LONGLONG *, LONGLONG *, struct _EPROCESS *, unsigned int, unsigned __int8, unsigned __int8, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoUnlockSingle)(_FILE_OBJECT *, LONGLONG *, LONGLONG *, struct _EPROCESS *, unsigned int, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoUnlockAll)(_FILE_OBJECT *, struct _EPROCESS *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoUnlockAllByKey)(_FILE_OBJECT *, void *, unsigned int, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoDeviceControl)(_FILE_OBJECT *, unsigned __int8, void *, unsigned int, void *, unsigned int, unsigned int, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    void (__fastcall *AcquireFileForNtCreateSection)(_FILE_OBJECT *);
    void (__fastcall *ReleaseFileForNtCreateSection)(_FILE_OBJECT *);
    void (__fastcall *FastIoDetachDevice)(_DEVICE_OBJECT *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoQueryNetworkOpenInfo)(_FILE_OBJECT *, unsigned __int8, _FILE_NETWORK_OPEN_INFORMATION *, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    int (__fastcall *AcquireForModWrite)(_FILE_OBJECT *, LONGLONG *, _ERESOURCE **, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *MdlRead)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned int, _MDL **, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *MdlReadComplete)(_FILE_OBJECT *, _MDL *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *PrepareMdlWrite)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned int, _MDL **, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *MdlWriteComplete)(_FILE_OBJECT *, LONGLONG *, _MDL *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoReadCompressed)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned int, void *, _MDL **, _IO_STATUS_BLOCK *, struct _COMPRESSED_DATA_INFO *, unsigned int, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoWriteCompressed)(_FILE_OBJECT *, LONGLONG *, unsigned int, unsigned int, void *, _MDL **, _IO_STATUS_BLOCK *, struct _COMPRESSED_DATA_INFO *, unsigned int, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *MdlReadCompleteCompressed)(_FILE_OBJECT *, _MDL *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *MdlWriteCompleteCompressed)(_FILE_OBJECT *, LONGLONG *, _MDL *, _DEVICE_OBJECT *);
    unsigned __int8 (__fastcall *FastIoQueryOpen)(_IRP *, _FILE_NETWORK_OPEN_INFORMATION *, _DEVICE_OBJECT *);
    int (__fastcall *ReleaseForModWrite)(_FILE_OBJECT *, _ERESOURCE *, _DEVICE_OBJECT *);
    int (__fastcall *AcquireForCcFlush)(_FILE_OBJECT *, _DEVICE_OBJECT *);
    int (__fastcall *ReleaseForCcFlush)(_FILE_OBJECT *, _DEVICE_OBJECT *);
};

struct _DRIVER_OBJECT {
    __int16 Type;
    __int16 Size;
    _DEVICE_OBJECT *DeviceObject;
    unsigned int Flags;
    void *DriverStart;
    unsigned int DriverSize;
    void *DriverSection;
    _DRIVER_EXTENSION *DriverExtension;
    _UNICODE_STRING DriverName;
    _UNICODE_STRING *HardwareDatabase;
    _FAST_IO_DISPATCH *FastIoDispatch;
    NTSTATUS (__fastcall *DriverInit)(_DRIVER_OBJECT *, _UNICODE_STRING *);
    void (__fastcall *DriverStartIo)(_DEVICE_OBJECT *, _IRP *);
    void (__fastcall *DriverUnload)(_DRIVER_OBJECT *);
    NTSTATUS (__fastcall *DispatchCreate)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchCreateNamedPipe)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchClose)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchRead)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchWrite)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchQueryInformation)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSetInformation)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchQueryEA)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSetEA)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchFlushBuffers)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchQueryVolumeInformation)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSetVolumeInformation)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchDirectoryControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchFileSystemControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchDeviceIOControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchInternalDeviceControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchShutdown)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchLockControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchCleanup)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchCreateMailslot)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchQuerySecurity)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSetSecurity)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchPower)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSystemControl)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchDeviceChange)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchQueryQuota)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchSetQuota)(_DEVICE_OBJECT *, _IRP *);
    NTSTATUS (__fastcall *DispatchPNP)(_DEVICE_OBJECT *, _IRP *);
};

typedef NTSTATUS __fastcall FN_WDF_DRIVER_DEVICE_ADD(WDFDRIVER Driver, WDFDEVICE_INIT *DeviceInit);
typedef VOID __fastcall FN_WDF_DRIVER_UNLOAD(WDFDRIVER Driver);

struct _WDF_DRIVER_CONFIG {
  ULONG                     Size;
  FN_WDF_DRIVER_DEVICE_ADD *EvtDriverDeviceAdd;
  FN_WDF_DRIVER_UNLOAD     *EvtDriverUnload;
  ULONG                     DriverInitFlags;
  ULONG                     DriverPoolTag;
};

struct _WDF_OBJECT_CONTEXT_TYPE_INFO {
  ULONG                          Size;
  PCHAR                          ContextName;
  size_t                         ContextSize;
  PVOID                          UniqueType;
  PVOID                          EvtDriverGetUniqueContextType;
};

enum _WDF_EXECUTION_LEVEL { 
  WdfExecutionLevelInvalid            = 0x00,
  WdfExecutionLevelInheritFromParent  = 0x1,
  WdfExecutionLevelPassive            = 0x2,
  WdfExecutionLevelDispatch           = 0x3
};

enum _WDF_SYNCHRONIZATION_SCOPE { 
  WdfSynchronizationScopeInvalid            = 0x00,
  WdfSynchronizationScopeInheritFromParent  = 0x1,
  WdfSynchronizationScopeDevice             = 0x2,
  WdfSynchronizationScopeQueue              = 0x3,
  WdfSynchronizationScopeNone               = 0x4
};

typedef VOID __fastcall FN_WDF_OBJECT_CONTEXT_CLEANUP(WDFOBJECT Object);
typedef VOID __fastcall FN_WDF_OBJECT_CONTEXT_DESTROY(WDFOBJECT Object);

struct _WDF_OBJECT_ATTRIBUTES {
  ULONG                          Size;
  FN_WDF_OBJECT_CONTEXT_CLEANUP *EvtCleanupCallback;
  FN_WDF_OBJECT_CONTEXT_DESTROY *EvtDestroyCallback;
  _WDF_EXECUTION_LEVEL            ExecutionLevel;
  _WDF_SYNCHRONIZATION_SCOPE      SynchronizationScope;
  WDFOBJECT                      ParentObject;
  size_t                         ContextSizeOverride;
  _WDF_OBJECT_CONTEXT_TYPE_INFO  *ContextTypeInfo;
};

struct _EVENT_FILTER_DESCRIPTOR {
  ULONGLONG Ptr;
  ULONG     Size;
  ULONG     Type;
};

struct _WPP_TRACE_CONTROL_BLOCK {
    int (__fastcall *Callback)(unsigned __int8, void *, unsigned int, void *, void *, unsigned int *);
    const _GUID *ControlGuid;
    _WPP_TRACE_CONTROL_BLOCK *Next;
    __int64 Logger;
    _UNICODE_STRING *RegistryPath;
    unsigned __int8 FlagsLen;
    unsigned __int8 Level;
    unsigned __int16 Reserved;
    unsigned int Flags[1];
    unsigned int ReservedFlags;
    unsigned __int64 RegHandle;
};

struct __declspec(align(4)) _KDEVICE_QUEUE {
    __int16 Type;
    __int16 Size;
    _LIST_ENTRY DeviceListHead;
    unsigned int Lock;
    unsigned __int8 Busy;
    // padding byte
    // padding byte
    // padding byte
};

struct _KDPC {
    unsigned __int8 Type;
    unsigned __int8 Importance;
    volatile unsigned __int16 Number;
    _LIST_ENTRY DpcListEntry;
    void (__fastcall *DeferredRoutine)(_KDPC *, void *, void *, void *);
    void *DeferredContext;
    void *SystemArgument1;
    void *SystemArgument2;
    void *DpcData;
};

struct _DEVOBJ_EXTENSION {
    __int16 Type;
    unsigned __int16 Size;
    _DRIVER_OBJECT *DeviceObject;
};

struct _DEVICE_OBJECT {
    __int16 Type;
    unsigned __int16 Size;
    int ReferenceCount;
    _DRIVER_OBJECT *DriverObject;
    _DEVICE_OBJECT *NextDevice;
    _DEVICE_OBJECT *AttachedDevice;
    _IRP *CurrentIrp;
    struct _IO_TIMER *Timer;
    unsigned int Flags;
    unsigned int Characteristics;
    _VPB *Vpb;
    void *DeviceExtension;
    unsigned int DeviceType;
    char StackSize;
    // padding byte
    // padding byte
    // padding byte
    __int8 Queue[0x28];
    unsigned int AlignmentRequirement;
    _KDEVICE_QUEUE DeviceQueue;
    _KDPC Dpc;
    unsigned int ActiveThreadCount;
    void *SecurityDescriptor;
    _KEVENT DeviceLock;
    unsigned __int16 SectorSize;
    unsigned __int16 Spare1;
    _DEVOBJ_EXTENSION *DeviceObjectExtension;
    void *Reserved;
};

struct _WDF_VERSION {
    unsigned int Major;
    unsigned int Minor;
    unsigned int Build;
};

struct _WDF_BIND_INFO {
    unsigned int Size;
    wchar_t *Component;
    _WDF_VERSION Version;
    unsigned int FuncCount;
    void (__fastcall **FuncTable)();
    PVOID Module;
};

struct _EVENT_DESCRIPTOR {
    unsigned __int16 Id;
    unsigned __int8 Version;
    unsigned __int8 Channel;
    unsigned __int8 Level;
    unsigned __int8 Opcode;
    unsigned __int16 Task;
    unsigned __int64 Keyword;
};

enum _WDF_POWER_DEVICE_STATE : __int32 {
    WdfPowerDeviceInvalid = 0x0,
    WdfPowerDeviceD0      = 0x1,
    WdfPowerDeviceD1      = 0x2,
    WdfPowerDeviceD2      = 0x3,
    WdfPowerDeviceD3      = 0x4,
    WdfPowerDeviceD3Final = 0x5,
    WdfPowerDevicePrepareForHibernation = 0x6,
    WdfPowerDeviceMaximum = 0x7,
};

enum _WDF_SPECIAL_FILE_TYPE : __int32 {
    WdfSpecialFileUndefined   = 0x0,
    WdfSpecialFilePaging      = 0x1,
    WdfSpecialFileHibernation = 0x2,
    WdfSpecialFileDump        = 0x3,
    WdfSpecialFileBoot        = 0x4,
    WdfSpecialFileMax         = 0x5,
};

enum _DEVICE_RELATION_TYPE : __int32 {
    BusRelations         = 0x0,
    EjectionRelations    = 0x1,
    PowerRelations       = 0x2,
    RemovalRelations     = 0x3,
    TargetDeviceRelation = 0x4,
    SingleBusRelations   = 0x5,
    TransportRelations   = 0x6,
};

struct _WDF_PNPPOWER_EVENT_CALLBACKS {
    unsigned int Size;
    int (__fastcall *EvtDeviceD0Entry)(WDFDEVICE, _WDF_POWER_DEVICE_STATE);
    int (__fastcall *EvtDeviceD0EntryPostInterruptsEnabled)(WDFDEVICE, _WDF_POWER_DEVICE_STATE);
    int (__fastcall *EvtDeviceD0Exit)(WDFDEVICE, _WDF_POWER_DEVICE_STATE);
    int (__fastcall *EvtDeviceD0ExitPreInterruptsDisabled)(WDFDEVICE, _WDF_POWER_DEVICE_STATE);
    int (__fastcall *EvtDevicePrepareHardware)(WDFDEVICE, WDFCMRESLIST, WDFCMRESLIST);
    int (__fastcall *EvtDeviceReleaseHardware)(WDFDEVICE, WDFCMRESLIST);
    void (__fastcall *EvtDeviceSelfManagedIoCleanup)(WDFDEVICE);
    void (__fastcall *EvtDeviceSelfManagedIoFlush)(WDFDEVICE);
    int (__fastcall *EvtDeviceSelfManagedIoInit)(WDFDEVICE);
    int (__fastcall *EvtDeviceSelfManagedIoSuspend)(WDFDEVICE);
    int (__fastcall *EvtDeviceSelfManagedIoRestart)(WDFDEVICE);
    void (__fastcall *EvtDeviceSurpriseRemoval)(WDFDEVICE);
    int (__fastcall *EvtDeviceQueryRemove)(WDFDEVICE);
    int (__fastcall *EvtDeviceQueryStop)(WDFDEVICE);
    void (__fastcall *EvtDeviceUsageNotification)(WDFDEVICE, _WDF_SPECIAL_FILE_TYPE, BOOLEAN);
    void (__fastcall *EvtDeviceRelationsQuery)(WDFDEVICE, _DEVICE_RELATION_TYPE);
    int (__fastcall *EvtDeviceUsageNotificationEx)(WDFDEVICE, _WDF_SPECIAL_FILE_TYPE, BOOLEAN);
};

enum _WDF_TRI_STATE : __int32 {
    WdfFalse      = 0x0,
    WdfTrue       = 0x1,
    WdfUseDefault = 0x2,
};

enum _WDF_FILEOBJECT_CLASS : __int32 {
    WdfFileObjectInvalid             = 0x0,
    WdfFileObjectNotRequired         = 0x1,
    WdfFileObjectWdfCanUseFsContext  = 0x2,
    WdfFileObjectWdfCanUseFsContext2 = 0x3,
    WdfFileObjectWdfCannotUseFsContexts = 0x4,
    WdfFileObjectCanBeOptional       = 0x80000000,
};

struct _WDF_FILEOBJECT_CONFIG {
    unsigned int Size;
    void (__fastcall *EvtDeviceFileCreate)(WDFDEVICE, WDFREQUEST, WDFFILEOBJECT);
    void (__fastcall *EvtFileClose)(WDFFILEOBJECT);
    void (__fastcall *EvtFileCleanup)(WDFFILEOBJECT);
    _WDF_TRI_STATE AutoForwardCleanupClose;
    _WDF_FILEOBJECT_CLASS FileObjectClass;
};

enum _WDF_IO_QUEUE_DISPATCH_TYPE : __int32 {
    WdfIoQueueDispatchInvalid    = 0x0,
    WdfIoQueueDispatchSequential = 0x1,
    WdfIoQueueDispatchParallel   = 0x2,
    WdfIoQueueDispatchManual     = 0x3,
    WdfIoQueueDispatchMax        = 0x4,
};

struct _WDF_IO_QUEUE_CONFIG {
    unsigned int Size;
    _WDF_IO_QUEUE_DISPATCH_TYPE DispatchType;
    _WDF_TRI_STATE PowerManaged;
    unsigned __int8 AllowZeroLengthRequests;
    unsigned __int8 DefaultQueue;
    // padding byte
    // padding byte
    void (__fastcall *EvtIoDefault)(WDFQUEUE, WDFREQUEST);
    void (__fastcall *EvtIoRead)(WDFQUEUE, WDFREQUEST, size_t);
    void (__fastcall *EvtIoWrite)(WDFQUEUE, WDFREQUEST, size_t);
    void (__fastcall *EvtIoDeviceControl)(WDFQUEUE, WDFREQUEST, size_t, size_t, ULONG);
    void (__fastcall *EvtIoInternalDeviceControl)(WDFQUEUE, WDFREQUEST, size_t, size_t, ULONG);
    void (__fastcall *EvtIoStop)(WDFQUEUE, WDFREQUEST, ULONG);
    void (__fastcall *EvtIoResume)(WDFQUEUE, WDFREQUEST);
    void (__fastcall *EvtIoCanceledOnQueue)(WDFQUEUE, WDFREQUEST);
    union {
      struct {
        ULONG NumberOfPresentedRequests;
      } Parallel;
    } Settings;
    WDFDRIVER Driver;
};

struct _INTERFACE {
    USHORT Size;
    USHORT Version;
    PVOID  Context;
    void (__fastcall *InterfaceReference)(void *);
    void (__fastcall *InterfaceDereference)(void *);
};

typedef NTSTATUS __fastcall FN_WDF_DEVICE_PROCESS_QUERY_INTERFACE_REQUEST( WDFDEVICE Device, GUID *InterfaceType, _INTERFACE *ExposedInterface, PVOID ExposedInterfaceSpecificData);

struct __declspec(align(4)) _WDF_QUERY_INTERFACE_CONFIG {
  ULONG                                          Size;
  _INTERFACE                                     *Interface;
  const GUID                                     *InterfaceType;
  BOOLEAN                                        SendQueryToParentStack;
  FN_WDF_DEVICE_PROCESS_QUERY_INTERFACE_REQUEST  *EvtDeviceProcessQueryInterfaceRequest;
  BOOLEAN                                        ImportInterface;
};

struct __declspec(align(4)) _WDF_INTERRUPT_CONFIG {
    ULONG Size;
    WDFSPINLOCK SpinLock;
    _WDF_TRI_STATE ShareVector;
    BOOLEAN FloatingSave;
    BOOLEAN AutomaticSerialization;
    // padding byte
    // padding byte
    BOOLEAN (__fastcall *EvtInterruptIsr)(WDFINTERRUPT , ULONG);
    void (__fastcall *EvtInterruptDpc)(WDFINTERRUPT , WDFOBJECT);
    int (__fastcall *EvtInterruptEnable)(WDFINTERRUPT , WDFDEVICE);
    int (__fastcall *EvtInterruptDisable)(WDFINTERRUPT , WDFDEVICE);
    void (__fastcall *EvtInterruptWorkItem)(WDFINTERRUPT , WDFOBJECT);
    PVOID InterruptRaw;
    PVOID InterruptTranslated;
    WDFWAITLOCK WaitLock;
    BOOLEAN PassiveHandling;
    // padding byte
    // padding byte
    // padding byte
};

enum _WDF_IO_TARGET_OPEN_TYPE : __int32 {
    WdfIoTargetOpenUndefined         = 0x0,
    WdfIoTargetOpenUseExistingDevice = 0x1,
    WdfIoTargetOpenByName            = 0x2,
    WdfIoTargetOpenReopen            = 0x3,
};

struct _WDF_IO_TARGET_OPEN_PARAMS {
  ULONG                             Size;
  _WDF_IO_TARGET_OPEN_TYPE          Type;
  NTSTATUS (__fastcall *EvtIoTargetQueryRemove)(WDFIOTARGET);
  void (__fastcall *EvtIoTargetRemoveCanceled)(WDFIOTARGET);
  void (__fastcall *EvtIoTargetRemoveComplete)(WDFIOTARGET);
  _DEVICE_OBJECT                    *TargetDeviceObject;
  _FILE_OBJECT                      *TargetFileObject;
  UNICODE_STRING                    TargetDeviceName;
  ULONG                             DesiredAccess;
  ULONG                             ShareAccess;
  ULONG                             FileAttributes;
  ULONG                             CreateDisposition;
  ULONG                             CreateOptions;
  PVOID                             EaBuffer;
  ULONG                             EaBufferLength;
  LONGLONG                          *AllocationSize;
  ULONG                             FileInformation;
};

enum _WDF_MEMORY_DESCRIPTOR_TYPE : __int32 {
    WdfMemoryDescriptorTypeInvalid = 0x0,
    WdfMemoryDescriptorTypeBuffer  = 0x1,
    WdfMemoryDescriptorTypeMdl     = 0x2,
    WdfMemoryDescriptorTypeHandle  = 0x3,
};

struct _WDFMEMORY_OFFSET {
    size_t BufferOffset;
    size_t BufferLength;
};

struct _WDF_MEMORY_DESCRIPTOR {
  _WDF_MEMORY_DESCRIPTOR_TYPE Type;
  union {
    struct {
      PVOID Buffer;
      ULONG Length;
    } BufferType;
    struct {
      _MDL  *Mdl;
      ULONG BufferLength;
    } MdlType;
    struct {
      WDFMEMORY         Memory;
      _WDFMEMORY_OFFSET *Offsets;
    } HandleType;
  } u;
};

struct _WDF_REQUEST_SEND_OPTIONS {
  ULONG    Size;
  ULONG    Flags;
  LONGLONG Timeout;
};

enum _WDF_REQUEST_TYPE : __int32 {
    WdfRequestTypeCreate            = 0x0,
    WdfRequestTypeCreateNamedPipe   = 0x1,
    WdfRequestTypeClose             = 0x2,
    WdfRequestTypeRead              = 0x3,
    WdfRequestTypeWrite             = 0x4,
    WdfRequestTypeQueryInformation  = 0x5,
    WdfRequestTypeSetInformation    = 0x6,
    WdfRequestTypeQueryEA           = 0x7,
    WdfRequestTypeSetEA             = 0x8,
    WdfRequestTypeFlushBuffers      = 0x9,
    WdfRequestTypeQueryVolumeInformation = 0xA,
    WdfRequestTypeSetVolumeInformation = 0xB,
    WdfRequestTypeDirectoryControl  = 0xC,
    WdfRequestTypeFileSystemControl = 0xD,
    WdfRequestTypeDeviceControl     = 0xE,
    WdfRequestTypeDeviceControlInternal = 0xF,
    WdfRequestTypeShutdown          = 0x10,
    WdfRequestTypeLockControl       = 0x11,
    WdfRequestTypeCleanup           = 0x12,
    WdfRequestTypeCreateMailSlot    = 0x13,
    WdfRequestTypeQuerySecurity     = 0x14,
    WdfRequestTypeSetSecurity       = 0x15,
    WdfRequestTypePower             = 0x16,
    WdfRequestTypeSystemControl     = 0x17,
    WdfRequestTypeDeviceChange      = 0x18,
    WdfRequestTypeQueryQuota        = 0x19,
    WdfRequestTypeSetQuota          = 0x1A,
    WdfRequestTypePnp               = 0x1B,
    WdfRequestTypeOther             = 0x1C,
    WdfRequestTypeUsb               = 0x40,
    WdfRequestTypeNoFormat          = 0xFF,
    WdfRequestTypeMax               = 0x100,
};

struct _WDF_REQUEST_PARAMETERS {
  USHORT           Size;
  UCHAR            MinorFunction;
  // padding byte
  _WDF_REQUEST_TYPE Type;
  union {
    struct {
      PVOID                    SecurityContext;
      ULONG                    Options;
      USHORT                   FileAttributes;
      USHORT                   ShareAccess;
      ULONG                    EaLength;
    } Create;
    struct {
      size_t                  Length;
      ULONG                   Key;
      LONGLONG                DeviceOffset;
    } Read;
    struct {
      size_t                  Length;
      ULONG                   Key;
      LONGLONG                DeviceOffset;
    } Write;
    struct {
      size_t                   OutputBufferLength;
      size_t                   InputBufferLength;
      ULONG                    IoControlCode;
      PVOID                    Type3InputBuffer;
    } DeviceIoControl;
    struct {
      PVOID                   Arg1;
      PVOID                   Arg2;
      ULONG                   IoControlCode;
      PVOID                   Arg4;
    } Others;
  } Parameters;
};

struct __declspec(align(4)) _WDF_WORKITEM_CONFIG {
  ULONG            Size;
  void (__fastcall *EvtWorkItemFunc)(WDFWORKITEM *);
  BOOLEAN          AutomaticSerialization;
};

enum _WPP_TRACE_API_SUITE : __int32 {
    WppTraceDisabledSuite = 0x0,
    WppTraceWin2K         = 0x1,
    WppTraceWinXP         = 0x2,
    WppTraceTraceLH       = 0x3,
    WppTraceServer08      = 0x4,
    WppTraceMaxSuite      = 0x5,
};

enum _TRACE_INFORMATION_CLASS : __int32 {
    TraceIdClass                   = 0x0,
    TraceHandleClass               = 0x1,
    TraceEnableFlagsClass          = 0x2,
    TraceEnableLevelClass          = 0x3,
    GlobalLoggerHandleClass        = 0x4,
    EventLoggerHandleClass         = 0x5,
    AllLoggerHandlesClass          = 0x6,
    TraceHandleByNameClass         = 0x7,
    LoggerEventsLostClass          = 0x8,
    TraceSessionSettingsClass      = 0x9,
    LoggerEventsLoggedClass        = 0xA,
    DiskIoNotifyRoutinesClass      = 0xB,
    TraceInformationClassReserved1 = 0xC,
    FltIoNotifyRoutinesClass       = 0xD,
    TraceInformationClassReserved2 = 0xE,
    WdfNotifyRoutinesClass         = 0xF,
    MaxTraceInformationClass       = 0x10,
};

enum _WDF_DEVICE_IO_TYPE : __int32 {
    WdfDeviceIoUndefined = 0x0,
    WdfDeviceIoNeither   = 0x1,
    WdfDeviceIoBuffered  = 0x2,
    WdfDeviceIoDirect    = 0x3,
};

enum _POOL_TYPE : __int32 {
    NonPagedPool                    = 0x0,
    NonPagedPoolExecute             = 0x0,
    PagedPool                       = 0x1,
    NonPagedPoolMustSucceed         = 0x2,
    DontUseThisType                 = 0x3,
    NonPagedPoolCacheAligned        = 0x4,
    PagedPoolCacheAligned           = 0x5,
    NonPagedPoolCacheAlignedMustS   = 0x6,
    MaxPoolType                     = 0x7,
    NonPagedPoolBase                = 0x0,
    NonPagedPoolBaseMustSucceed     = 0x2,
    NonPagedPoolBaseCacheAligned    = 0x4,
    NonPagedPoolBaseCacheAlignedMustS = 0x6,
    NonPagedPoolSession             = 0x20,
    PagedPoolSession                = 0x21,
    NonPagedPoolMustSucceedSession  = 0x22,
    DontUseThisTypeSession          = 0x23,
    NonPagedPoolCacheAlignedSession = 0x24,
    PagedPoolCacheAlignedSession    = 0x25,
    NonPagedPoolCacheAlignedMustSSession = 0x26,
    NonPagedPoolNx                  = 0x200,
    NonPagedPoolNxCacheAligned      = 0x204,
    NonPagedPoolSessionNx           = 0x220,
};

struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG                *ExceptionInformation[15];
};

struct _NEON128 {
    unsigned __int64 Low;
    __int64 High;
};

struct _CONTEXT {
    unsigned int ContextFlags;
    unsigned int R0;
    unsigned int R1;
    unsigned int R2;
    unsigned int R3;
    unsigned int R4;
    unsigned int R5;
    unsigned int R6;
    unsigned int R7;
    unsigned int R8;
    unsigned int R9;
    unsigned int R10;
    unsigned int R11;
    unsigned int R12;
    unsigned int Sp;
    unsigned int Lr;
    unsigned int Pc;
    unsigned int Cpsr;
    unsigned int Fpscr;
    unsigned int Padding;
    union {
        _NEON128 Q[16];
        unsigned __int64 D[32];
        unsigned int S[32];
    } ___u20;
    unsigned int Bvr[8];
    unsigned int Bcr[8];
    unsigned int Wvr[1];
    unsigned int Wcr[1];
    unsigned int Padding2[2];
};

enum _EXCEPTION_DISPOSITION : __int32 {
    ExceptionContinueExecution = 0x0,
    ExceptionContinueSearch    = 0x1,
    ExceptionNestedException   = 0x2,
    ExceptionCollidedUnwind    = 0x3,
};

struct _DISPATCHER_CONTEXT {
    unsigned int ControlPc;
    unsigned int ImageBase;
    PVOID FunctionEntry;
    unsigned int EstablisherFrame;
    unsigned int TargetPc;
    _CONTEXT *ContextRecord;
    _EXCEPTION_DISPOSITION (__fastcall *LanguageHandler)(_EXCEPTION_RECORD *, void *, _CONTEXT *, void *);
    void *HandlerData;
    PVOID HistoryTable;
    unsigned int ScopeIndex;
    unsigned __int8 ControlPcIsUnwound;
    // padding byte
    // padding byte
    // padding byte
    unsigned __int8 *NonVolatileRegisters;
    unsigned int Reserved;
};

enum _EVENT_TYPE {
  NotificationEvent,
  SynchronizationEvent
};

enum MY_BOOLEAN : __int8 {
    FALSE = 0x0,
    TRUE = 0x1
};

enum MY_NULL : __int32 {
    NULL = 0x0
};

enum _KPROCESSOR_MODE {
  KernelMode,
  UserMode,
  MaximumMode
};

enum _KWAIT_REASON {
  Executive,
  FreePage,
  PageIn,
  PoolAllocation,
  DelayExecution,
  Suspended,
  UserRequest,
  WrExecutive,
  WrFreePage,
  WrPageIn,
  WrPoolAllocation,
  WrDelayExecution,
  WrSuspended,
  WrUserRequest,
  WrEventPair,
  WrQueue,
  WrLpcReceive,
  WrLpcReply,
  WrVirtualMemory,
  WrPageOut,
  WrRendezvous,
  WrKeyedEvent,
  WrTerminated,
  WrProcessInSwap,
  WrCpuRateControl,
  WrCalloutStack,
  WrKernel,
  WrResource,
  WrPushLock,
  WrMutex,
  WrQuantumEnd,
  WrDispatchInt,
  WrPreempted,
  WrYieldExecution,
  WrFastMutex,
  WrGuardedMutex,
  WrRundown,
  MaximumWaitReason
};

enum _IO_NOTIFICATION_EVENT_CATEGORY {
  EventCategoryReserved,
  EventCategoryHardwareProfileChange,
  EventCategoryDeviceInterfaceChange,
  EventCategoryTargetDeviceChange,
  EventCategoryKernelSoftRestart
};

typedef NTSTATUS __fastcall DRIVER_NOTIFICATION_CALLBACK_ROUTINE(PVOID NotificationStructure, PVOID Context);

enum _MEMORY_CACHING_TYPE {
  MmNonCached,
  MmCached,
  MmWriteCombined,
  MmHardwareCoherentCached,
  MmNonCachedUnordered,
  MmUSWCCached,
  MmMaximumCacheType,
  MmNotMapped
};