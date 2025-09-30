// See https://learn.microsoft.com/
// See https://github.com/IOActive/kmdf_re/blob/master/code/WDFStructs.h

typedef unsigned __int16 wchar_t;
typedef unsigned __int16 wchar_t;
typedef wchar_t *PWSTR;
typedef unsigned int size_t;
typedef int NTSTATUS;
typedef void *WDFOBJECT;
typedef unsigned int ULONG;
typedef void VOID;
typedef void *PVOID;
typedef void *WDFCOLLECTION;
typedef void *WDFIOTARGET;
typedef void *WDFINTERRUPT;
typedef unsigned char BYTE;
typedef BYTE BOOLEAN;
typedef unsigned short USHORT;
typedef short SHORT;
typedef void *INTERFACE;
typedef void *WDFMEMORY;
typedef void *WDFLOOKASIDE;
typedef long LONG;
typedef void *PIRP;
typedef void *WDFWAITLOCK;
typedef void *WDFSPINLOCK;
typedef void *WDFWORKITEM;
typedef void *WDFDRIVER;
typedef void *WDFDEVICE_INIT;
typedef unsigned __int64 LONGLONG;

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