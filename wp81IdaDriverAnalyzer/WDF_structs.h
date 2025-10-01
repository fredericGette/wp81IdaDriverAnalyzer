// See https://learn.microsoft.com/
// See https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
// See https://github.com/IOActive/kmdf_re/blob/master/code/WDFStructs.h

typedef unsigned __int16 wchar_t;
typedef wchar_t *PWSTR;
typedef unsigned int size_t;
typedef unsigned char BYTE;
typedef unsigned int ULONG;
typedef long LONG;
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONGLONG;
typedef unsigned short USHORT;
typedef short SHORT;
typedef void VOID;
typedef BYTE BOOLEAN;
typedef void *PVOID;
typedef char CHAR;
typedef CHAR *PCHAR;
typedef void *INTERFACE;
typedef void *PIRP;
typedef int NTSTATUS;
typedef void *WDFCMRESLIST;
typedef void *WDFCOLLECTION;
typedef void *WDFDEVICE;
typedef void *WDFDEVICE_INIT;
typedef void *WDFDRIVER;
typedef void *WDFFILEOBJECT;
typedef void *WDFINTERRUPT;
typedef void *WDFIOTARGET;
typedef void *WDFLOOKASIDE;
typedef void *WDFMEMORY;
typedef void *WDFOBJECT;
typedef void *WDFQUEUE;
typedef void *WDFREQUEST;
typedef void *WDFSPINLOCK;
typedef void *WDFWAITLOCK;
typedef void *WDFWORKITEM;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _DRIVER_OBJECT {
     SHORT Type;
     SHORT Size;
     PVOID DeviceObject;
     ULONG Flags;
     PVOID DriverStart;
     ULONG DriverSize;
     PVOID DriverSection;
     PVOID DriverExtension;
     UNICODE_STRING DriverName;
     PUNICODE_STRING HardwareDatabase;
     PVOID FastIoDispatch;
     PVOID DriverInit;
     PVOID DriverStartIo;
     PVOID DriverUnload;
     PVOID DispatchCreate;
     PVOID DispatchCreateNamedPipe;
     PVOID DispatchClose;
     PVOID DispatchRead;
     PVOID DispatchWrite;
     PVOID DispatchQueryInformation;
     PVOID DispatchSetInformation;
     PVOID DispatchQueryEA;
     PVOID DispatchSetEA;
     PVOID DispatchFlushBuffers;
     PVOID DispatchQueryVolumeInformation;
     PVOID DispatchSetVolumeInformation;
     PVOID DispatchDirectoryControl;
     PVOID DispatchFileSystemControl;
     PVOID DispatchDeviceIOControl;
     PVOID DispatchInternalDeviceControl;
     PVOID DispatchShutdown;
     PVOID DispatchLockControl;
     PVOID DispatchCleanup;
     PVOID DispatchCreateMailslot;
     PVOID DispatchQuerySecurity;
     PVOID DispatchSetSecurity;
     PVOID DispatchPower;
     PVOID DispatchSystemControl;
     PVOID DispatchDeviceChange;
     PVOID DispatchQueryQuota;
     PVOID DispatchSetQuota;
     PVOID DispatchPNP;
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef NTSTATUS __fastcall FN_WDF_DRIVER_DEVICE_ADD(WDFDRIVER Driver, WDFDEVICE_INIT *DeviceInit);
typedef VOID __fastcall FN_WDF_DRIVER_UNLOAD(WDFDRIVER Driver);

typedef struct _WDF_DRIVER_CONFIG {
  ULONG                     Size;
  FN_WDF_DRIVER_DEVICE_ADD *EvtDriverDeviceAdd;
  FN_WDF_DRIVER_UNLOAD     *EvtDriverUnload;
  ULONG                     DriverInitFlags;
  ULONG                     DriverPoolTag;
} WDF_DRIVER_CONFIG, *PWDF_DRIVER_CONFIG;

typedef struct _WDF_OBJECT_CONTEXT_TYPE_INFO {
  ULONG                          Size;
  PCHAR                          ContextName;
  size_t                         ContextSize;
  PVOID                          UniqueType;
  PVOID                          EvtDriverGetUniqueContextType;
} WDF_OBJECT_CONTEXT_TYPE_INFO, *PWDF_OBJECT_CONTEXT_TYPE_INFO;

typedef enum _WDF_EXECUTION_LEVEL { 
  WdfExecutionLevelInvalid            = 0x00,
  WdfExecutionLevelInheritFromParent  = 0x1,
  WdfExecutionLevelPassive            = 0x2,
  WdfExecutionLevelDispatch           = 0x3
} WDF_EXECUTION_LEVEL;

typedef enum _WDF_SYNCHRONIZATION_SCOPE { 
  WdfSynchronizationScopeInvalid            = 0x00,
  WdfSynchronizationScopeInheritFromParent  = 0x1,
  WdfSynchronizationScopeDevice             = 0x2,
  WdfSynchronizationScopeQueue              = 0x3,
  WdfSynchronizationScopeNone               = 0x4
} WDF_SYNCHRONIZATION_SCOPE;

typedef VOID __fastcall FN_WDF_OBJECT_CONTEXT_CLEANUP(WDFOBJECT Object);
typedef VOID __fastcall FN_WDF_OBJECT_CONTEXT_DESTROY(WDFOBJECT Object);


typedef struct _WDF_OBJECT_ATTRIBUTES {
  ULONG                          Size;
  FN_WDF_OBJECT_CONTEXT_CLEANUP *EvtCleanupCallback;
  FN_WDF_OBJECT_CONTEXT_DESTROY *EvtDestroyCallback;
  WDF_EXECUTION_LEVEL            ExecutionLevel;
  WDF_SYNCHRONIZATION_SCOPE      SynchronizationScope;
  WDFOBJECT                      ParentObject;
  size_t                         ContextSizeOverride;
  PWDF_OBJECT_CONTEXT_TYPE_INFO  ContextTypeInfo;
} WDF_OBJECT_ATTRIBUTES, *PWDF_OBJECT_ATTRIBUTES;

typedef struct _EVENT_FILTER_DESCRIPTOR {
  ULONGLONG Ptr;
  ULONG     Size;
  ULONG     Type;
} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

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

struct _LIST_ENTRY {
    _LIST_ENTRY *Flink;
    _LIST_ENTRY *Blink;
};

struct _IO_STATUS_BLOCK {
    union {
        int Status;
        void *Pointer;
    } ___u0;
    unsigned int Information;
};

struct _KEVENT {
    __int8 Header[0x10]; // structure _DISPATCHER_HEADER
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
    __int8 Overlay[0x08];
    void (__fastcall *CancelRoutine)(void *deviceObject, _IRP *);
    void *UserBuffer;
    __int8 Tail[0x30];
};



// struct _DEVICE_OBJECT {
    // __int16 Type;
    // unsigned __int16 Size;
    // int ReferenceCount;
    // _DRIVER_OBJECT *DriverObject;
    // _DEVICE_OBJECT *NextDevice;
    // _DEVICE_OBJECT *AttachedDevice;
    // _IRP *CurrentIrp;
    // struct _IO_TIMER *Timer;
    // unsigned int Flags;
    // unsigned int Characteristics;
    // _VPB *Vpb;
    // void *DeviceExtension;
    // unsigned int DeviceType;
    // char StackSize;
    // // padding byte
    // // padding byte
    // // padding byte
    // _DEVICE_OBJECT Queue;
    // unsigned int AlignmentRequirement;
    // _KDEVICE_QUEUE DeviceQueue;
    // _KDPC Dpc;
    // unsigned int ActiveThreadCount;
    // void *SecurityDescriptor;
    // _KEVENT DeviceLock;
    // unsigned __int16 SectorSize;
    // unsigned __int16 Spare1;
    // _DEVOBJ_EXTENSION *DeviceObjectExtension;
    // void *Reserved;
// };