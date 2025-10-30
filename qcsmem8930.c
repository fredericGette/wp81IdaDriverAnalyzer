// Function: DoTraceMessage_01
int __fastcall DoTraceMessage_01(unsigned __int64 a1, unsigned __int16 a2, const _GUID *a3)
{
  return pfnWppTraceMessage(a1, 0x2Bu, a3, a2);
}


// Function: DoTraceMessage_02
int DoTraceMessage_02(unsigned __int64 a1, unsigned __int16 a2, int a3, ...)
{
  va_list va; // [sp+30h] [bp+18h] BYREF

  va_start(va, a3);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2, va, 4, 0);
}


// Function: DoTraceMessage_03
int DoTraceMessage_03(unsigned __int64 a1, int a2, int a3, ...)
{
  int v4; // [sp+38h] [bp+18h] BYREF
  va_list va; // [sp+38h] [bp+18h]
  va_list va1; // [sp+3Ch] [bp+1Ch] BYREF

  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, 0x1Bu, va, 4, va1, 4, 0);
}


// Function: DoTraceMessage_04
int DoTraceMessage_04(unsigned __int64 a1, unsigned __int16 a2, const _GUID *a3, ...)
{
  va_list va; // [sp+30h] [bp+18h] BYREF

  va_start(va, a3);
  return pfnWppTraceMessage(a1, 0x2Bu, a3, a2, va, 4, 0);
}


// Function: DoTraceMessage_05
int DoTraceMessage_05(unsigned __int64 a1, unsigned __int16 a2, const _GUID *a3, ...)
{
  int v4; // [sp+38h] [bp+18h] BYREF
  va_list va; // [sp+38h] [bp+18h]
  va_list va1; // [sp+3Ch] [bp+1Ch] BYREF

  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  return pfnWppTraceMessage(a1, 0x2Bu, a3, a2, va, 4, va1, 4, 0);
}


// Function: DoTraceMessage_06
int DoTraceMessage_06(unsigned __int64 a1, unsigned __int16 a2, int a3, ...)
{
  int v4; // [sp+40h] [bp+18h] BYREF
  va_list va; // [sp+40h] [bp+18h]
  int v6; // [sp+44h] [bp+1Ch]
  void *v7; // [sp+48h] [bp+20h] BYREF
  va_list va1; // [sp+48h] [bp+20h]
  int v9; // [sp+4Ch] [bp+24h]
  va_list va2; // [sp+50h] [bp+28h] BYREF

  va_start(va2, a3);
  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  v6 = va_arg(va1, _DWORD);
  va_copy(va2, va1);
  v7 = va_arg(va2, void *);
  v9 = va_arg(va2, _DWORD);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2, va, 4, va1, 8, va2, 4, 0);
}


// Function: DoTraceMessage_07
int DoTraceMessage_07(unsigned __int64 a1, unsigned __int16 a2, int a3, ...)
{
  int v4; // [sp+38h] [bp+18h] BYREF
  va_list va; // [sp+38h] [bp+18h]
  int v6; // [sp+3Ch] [bp+1Ch]
  va_list va1; // [sp+40h] [bp+20h] BYREF

  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  v6 = va_arg(va1, _DWORD);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2, va, 8, va1, 4, 0);
}


// Function: sub_4011C8
void __fastcall sub_4011C8(int a1, unsigned int a2, int a3, int a4)
{
  if ( a2 <= 1 )
  {
    if ( a2 )
    {
      *(_DWORD *)(a4 + 32) = *(_DWORD *)(a3 + 4);
      *(_BYTE *)(a4 + 29) = *(_BYTE *)(a3 + 2);
      *(_DWORD *)(a4 + 16) = *(_DWORD *)a3;
      *(_DWORD *)(a4 + 20) = *(_DWORD *)(a3 + 4);
    }
    else
    {
      *(_BYTE *)(a4 + 29) = 0;
      *(_DWORD *)(a4 + 32) = 0;
      *(_DWORD *)(a4 + 16) = 0;
      *(_DWORD *)(a4 + 20) = 0;
    }
  }
}


// Function: DriverEntry
int __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)
{
  _DEVICE_OBJECT *TracingSupport; // r0
  const _UNICODE_STRING *v5; // r1
  _DEVICE_OBJECT *v6; // r0
  int v7; // r4
  unsigned __int64 v8; // r0
  _WDF_DRIVER_CONFIG DriverConfig; // [sp+8h] [bp-20h] BYREF

  dword_405B20 = 0;
  pETW_provider_GUID = (int)&ETW_Provider_GUID_01;
  dword_405B28 = 0;
  dword_405B38 = 0;
  byte_405B3C = 1;
  byte_405B3D = 0;
  word_405B3E = 0;
  dword_405B40 = 0;
  TracingSupport = (_DEVICE_OBJECT *)WppLoadTracingSupport();
  dword_405B38 = 0;
  WppInitKm(TracingSupport, v5);
  memset(&DriverConfig.EvtDriverUnload, 0, 12);
  DriverConfig.Size = 20;
  DriverConfig.EvtDriverDeviceAdd = EvtDriverDeviceAdd;
  v6 = (_DEVICE_OBJECT *)WdfFunctions.WdfDriverCreate(WdfDriverGlobals, DriverObject, RegistryPath, 0, &DriverConfig, 0);
  v7 = (int)v6;
  if ( (int)v6 >= 0 )
    return 0;
  if ( (*((_DWORD *)off_405130 + 8) & 1) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
  {
    LODWORD(v8) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v8) = *((_DWORD *)off_405130 + 5);
    v6 = (_DEVICE_OBJECT *)DoTraceMessage_04(v8, 0xAu, &WPP_Traceguids_01, v7);
  }
  WppCleanupKm(v6);
  return v7;
}


// Function: EvtDriverDeviceAdd
// local variable allocation has failed, the output may be wrong!
NTSTATUS __fastcall EvtDriverDeviceAdd(WDFDRIVER Driver, WDFDEVICE_INIT *DeviceInit)
{
  NTSTATUS v2; // r4
  unsigned __int64 v3; // r0
  NTSTATUS result; // r0
  unsigned __int64 v5; // r0
  unsigned __int64 v6; // r0
  unsigned __int64 v7; // r0
  unsigned __int64 v8; // r0
  WDFDEVICE_INIT *v9; // [sp+8h] [bp-E0h] BYREF
  void *v10; // [sp+Ch] [bp-DCh] BYREF
  UNICODE_STRING v11; // [sp+10h] [bp-D8h] BYREF
  _WDF_IO_QUEUE_CONFIG Config; // [sp+18h] [bp-D0h] BYREF
  _WDF_FILEOBJECT_CONFIG FileObjectConfig; // [sp+50h] [bp-98h] BYREF
  _BYTE v14[8]; // [sp+68h] [bp-80h] BYREF
  _WDF_PNPPOWER_EVENT_CALLBACKS PnpPowerEventCallbacks; // [sp+70h] [bp-78h] BYREF
  wchar_t v16[3]; // [sp+B8h] [bp-30h] BYREF

  v9 = DeviceInit;
  wcscpy(v16, L"\\Device\\SMEM");
  v11.Length = 24;
  v11.MaximumLength = 26;
  v11.Buffer = v16;
  ((void (__fastcall *)(int, WDFDEVICE_INIT *, _DWORD))WdfFunctions.WdfDeviceInitSetExclusive)(
    WdfDriverGlobals,
    DeviceInit,
    0);
  WdfFunctions.WdfDeviceInitSetIoType(WdfDriverGlobals, v9, WdfDeviceIoBuffered);
  v2 = WdfFunctions.WdfDeviceInitAssignName(WdfDriverGlobals, v9, &v11);
  if ( v2 < 0 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
    {
      LODWORD(v3) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v3) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_04(v3, 0xBu, &WPP_Traceguids_01, v2);
    }
    return v2;
  }
  memset(&PnpPowerEventCallbacks, 0, sizeof(PnpPowerEventCallbacks));
  PnpPowerEventCallbacks.Size = 72;
  PnpPowerEventCallbacks.EvtDevicePrepareHardware = EvtWdfDevicePrepareHardware;
  PnpPowerEventCallbacks.EvtDeviceReleaseHardware = EvtWdfDeviceReleaseHardware;
  PnpPowerEventCallbacks.EvtDeviceSurpriseRemoval = EvtWdfDeviceSurpriseRemoval;
  WdfFunctions.WdfDeviceInitSetPnpPowerEventCallbacks(WdfDriverGlobals, v9, &PnpPowerEventCallbacks);
  FileObjectConfig.Size = 24;
  FileObjectConfig.EvtDeviceFileCreate = EvtWdfDeviceFileCreate;
  FileObjectConfig.EvtFileClose = 0;
  FileObjectConfig.EvtFileCleanup = 0;
  FileObjectConfig.FileObjectClass = WdfFileObjectWdfCannotUseFsContexts;
  FileObjectConfig.AutoForwardCleanupClose = WdfUseDefault;
  WdfFunctions.WdfDeviceInitSetFileObjectConfig(WdfDriverGlobals, v9, &FileObjectConfig, 0);
  v2 = WdfFunctions.WdfDeviceCreate(WdfDriverGlobals, &v9, 0, &v10);
  if ( v2 < 0 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
    {
      LODWORD(v5) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v5) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_04(v5, 0xCu, &WPP_Traceguids_01, v2);
      return v2;
    }
    return v2;
  }
  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
  {
    LODWORD(v6) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v6) = *((_DWORD *)off_405130 + 5);
    DoTraceMessage_02(v6, 0xDu, (int)v10, v10);
  }
  v2 = WdfFunctions.WdfDeviceCreateDeviceInterface(WdfDriverGlobals, v10, &InterfaceClassGUID_00, 0);
  if ( v2 >= 0 )
  {
    WdfFunctions.WdfDeviceSetStaticStopRemove(WdfDriverGlobals, v10, 0);
    *(_DWORD *)&Config.AllowZeroLengthRequests = 256;
    memset(&Config.EvtIoDefault, 0, 16);
    memset(&Config.EvtIoStop, 0, 12);
    Config.Driver = 0;
    Config.Size = 56;
    Config.DispatchType = WdfIoQueueDispatchParallel;
    Config.Settings.Parallel.NumberOfPresentedRequests = -1;
    Config.EvtIoInternalDeviceControl = EvtWdfIoQueueIoInternalDeviceControl;
    Config.PowerManaged = WdfFalse;
    result = WdfFunctions.WdfIoQueueCreate(WdfDriverGlobals, v10, &Config, 0, (WDFQUEUE *)v14);
    v2 = result;
    if ( result < 0 )
    {
      if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
        return v2;
      LODWORD(v8) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v8) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_04(v8, 0xFu, &WPP_Traceguids_01, v2);
      return v2;
    }
  }
  else
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
      return v2;
    LODWORD(v7) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v7) = *((_DWORD *)off_405130 + 5);
    DoTraceMessage_04(v7, 0xEu, &WPP_Traceguids_01, v2);
    return v2;
  }
  return result;
}


// Function: EvtWdfDevicePrepareHardware
NTSTATUS __fastcall EvtWdfDevicePrepareHardware(
        WDFDEVICE Device,
        WDFCMRESLIST ResourcesRaw,
        WDFCMRESLIST ResourcesTranslated)
{
  unsigned __int64 v4; // r0
  int v6; // r7
  unsigned __int8 *v7; // r0
  unsigned __int8 *v8; // r5
  unsigned __int64 v9; // r0
  size_t v10; // r2
  LONGLONG v11; // r0
  unsigned __int64 v12; // r0
  unsigned __int64 v13; // r0
  LONGLONG v14; // r0
  unsigned __int64 v15; // r0
  _DWORD *v16; // r4
  int v17; // r3
  unsigned __int64 v18; // r0
  PVOID v19; // r0
  int v20; // r2
  int v21; // r3
  unsigned __int64 v22; // r0
  void *v23; // r0
  _DWORD *v24; // r2
  unsigned __int64 v25; // r0
  unsigned __int64 v26; // r0
  unsigned __int64 v27; // r0
  unsigned __int64 v28; // r0
  unsigned __int64 v29; // r0
  int v30; // r3
  unsigned __int64 v31; // r0

  if ( (unsigned int)((int (__fastcall *)(int, WDFCMRESLIST))WdfFunctions.WdfCmResourceListGetCount)(
                       WdfDriverGlobals,
                       ResourcesTranslated) > 2 )
  {
    dword_405AE4 = ((int (__fastcall *)(int, WDFCMRESLIST))WdfFunctions.WdfCmResourceListGetCount)(
                     WdfDriverGlobals,
                     ResourcesTranslated)
                 - 2;
    dword_405AF4 = (int)ExAllocatePoolWithTag(NonPagedPoolNx, 8 * dword_405AE4, '1esq');
    if ( !dword_405AF4 )
    {
      if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
      {
        LODWORD(v4) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v4) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_04(v4, 0x10u, &WPP_Traceguids_01, dword_405AE4);
      }
      return STATUS_INSUFFICIENT_RESOURCES;
    }
  }
  v6 = 0;
  if ( !((int (__fastcall *)(int, WDFCMRESLIST))WdfFunctions.WdfCmResourceListGetCount)(
          WdfDriverGlobals,
          ResourcesTranslated) )
  {
LABEL_35:
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
    {
      LODWORD(v22) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v22) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v22, 0x1Au, &WPP_Traceguids_01);
    }
    smem_init();
    dword_40516C = (int)smem_alloc(dword_40515C, 20 * dword_405158);
    v23 = smem_alloc(dword_405160, 4);
    dword_405170 = (int)v23;
    if ( dword_405164 != SMEM_VOICE )
    {
      dword_405174 = (int)smem_alloc(dword_405164, 4);
      v23 = (void *)dword_405170;
    }
    if ( !dword_40516C || !v23 )
    {
      v24 = off_405130;
      if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || !*((_BYTE *)off_405130 + 29) )
        goto LABEL_46;
      LODWORD(v25) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v25) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v25, 0xAu, &stru_404158);
    }
    v24 = off_405130;
LABEL_46:
    if ( (v24[8] & 2) != 0 && *((unsigned __int8 *)v24 + 29) >= 4u )
    {
      LODWORD(v26) = v24[4];
      HIDWORD(v26) = v24[5];
      DoTraceMessage_03(v26, (int)v24, dword_405AE0, dword_405AE0, dword_405AF0);
    }
    return 0;
  }
  while ( 1 )
  {
    v7 = (unsigned __int8 *)((int (__fastcall *)(int, WDFCMRESLIST, int))WdfFunctions.WdfCmResourceListGetDescriptor)(
                              WdfDriverGlobals,
                              ResourcesTranslated,
                              v6);
    v8 = v7;
    if ( !v7 )                                  // CmResourceTypeNull
      return STATUS_DEVICE_CONFIGURATION_ERROR;
    if ( *v7 != 3 )                             // CmResourceTypeMemory
      break;
    if ( v6 )
    {
      if ( v6 == 1 )
      {
        if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
        {
          LODWORD(v13) = *((_DWORD *)off_405130 + 4);
          HIDWORD(v13) = *((_DWORD *)off_405130 + 5);
          DoTraceMessage_07(
            v13,
            0x13u,
            *((_DWORD *)v8 + 2),
            *((_DWORD *)v8 + 1),
            *((_DWORD *)v8 + 2),
            *((_DWORD *)v8 + 3));
        }
        v14 = *(_QWORD *)(v8 + 4);              // v8+4:u.Memory.Start
        dword_405AE8 = *((_DWORD *)v8 + 3);
        dword_405B50 = (int)MmMapIoSpace(v14, dword_405AE8, MmNonCached);
        if ( !dword_405B50 )
        {
          if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
          {
            LODWORD(v27) = *((_DWORD *)off_405130 + 4);
            HIDWORD(v27) = *((_DWORD *)off_405130 + 5);
            DoTraceMessage_07(
              v27,
              0x14u,
              *((_DWORD *)v8 + 2),
              *((_DWORD *)v8 + 1),
              *((_DWORD *)v8 + 2),
              *((_DWORD *)v8 + 3));
            return STATUS_DEVICE_CONFIGURATION_ERROR;
          }
          return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        if ( (unsigned int)dword_405AE8 < 32 )
        {
          if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
          {
            LODWORD(v15) = *((_DWORD *)off_405130 + 4);
            HIDWORD(v15) = *((_DWORD *)off_405130 + 5);
            DoTraceMessage_05(v15, 0x15u, &WPP_Traceguids_01, 8, (unsigned int)dword_405AE8 >> 2);
            return STATUS_DEVICE_CONFIGURATION_ERROR;
          }
          return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
      }
      else
      {
        v16 = off_405130;
        if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
        {
          v17 = *((_DWORD *)v7 + 1);
          LODWORD(v18) = *((_DWORD *)off_405130 + 4);
          HIDWORD(v18) = *((_DWORD *)off_405130 + 5);
          DoTraceMessage_06(v18, 0x16u, v17, v6 - 2);
          v16 = off_405130;
        }
        if ( *((_DWORD *)v8 + 3) != 4 )
        {
          if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
          {
            LODWORD(v29) = v16[4];
            HIDWORD(v29) = v16[5];
            DoTraceMessage_05(v29, 0x17u, &WPP_Traceguids_01, v6 - 2, *((_DWORD *)v8 + 3));
            return STATUS_DEVICE_CONFIGURATION_ERROR;
          }
          return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        v19 = MmMapIoSpace(*(_QWORD *)(v8 + 4), 4u, MmNonCached);// v8+4:u.Memory.Start
        if ( !v19 )
        {
          if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
          {
            LODWORD(v28) = *((_DWORD *)off_405130 + 4);
            HIDWORD(v28) = *((_DWORD *)off_405130 + 5);
            DoTraceMessage_06(v28, 0x18u, v6 - 2, v6 - 2);
            return STATUS_DEVICE_CONFIGURATION_ERROR;
          }
          return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        v20 = dword_405AF4 + 8 * v6;
        v21 = *((_DWORD *)v8 + 1);
        *(_DWORD *)(v20 - 12) = v19;
        *(_DWORD *)(v20 - 16) = v21;
      }
    }
    else
    {
      if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
      {
        LODWORD(v9) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v9) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_07(v9, 0x11u, *((_DWORD *)v8 + 2), *((_DWORD *)v8 + 1), *((_DWORD *)v8 + 2), *((_DWORD *)v8 + 3));
      }
      v10 = *((_DWORD *)v8 + 3);
      HIDWORD(v11) = *((_DWORD *)v8 + 2);
      dword_405AEC = *((_DWORD *)v8 + 1);
      LODWORD(v11) = dword_405AEC;
      dword_405AF0 = v10;
      dword_405AE0 = (int)MmMapIoSpace(v11, v10, MmWriteCombined);
      if ( !dword_405AE0 )
      {
        if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 2u )
        {
          LODWORD(v12) = *((_DWORD *)off_405130 + 4);
          HIDWORD(v12) = *((_DWORD *)off_405130 + 5);
          DoTraceMessage_07(
            v12,
            0x12u,
            *((_DWORD *)v8 + 2),
            *((_DWORD *)v8 + 1),
            *((_DWORD *)v8 + 2),
            *((_DWORD *)v8 + 3));
        }
        return STATUS_DEVICE_CONFIGURATION_ERROR;
      }
    }
    if ( ++v6 >= (unsigned int)((int (__fastcall *)(int, WDFCMRESLIST))WdfFunctions.WdfCmResourceListGetCount)(
                                 WdfDriverGlobals,
                                 ResourcesTranslated) )
      goto LABEL_35;
  }
  if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  v30 = *v7;
  LODWORD(v31) = *((_DWORD *)off_405130 + 4);
  HIDWORD(v31) = *((_DWORD *)off_405130 + 5);
  DoTraceMessage_02(v31, 0x19u, v30, *v8);
  return STATUS_DEVICE_CONFIGURATION_ERROR;
}


// Function: EvtWdfDeviceReleaseHardware
NTSTATUS __fastcall EvtWdfDeviceReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  unsigned __int64 v2; // r0
  _DWORD *v3; // r0
  int i; // r5

  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
  {
    LODWORD(v2) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v2) = *((_DWORD *)off_405130 + 5);
    DoTraceMessage_01(v2, 0x1Cu, &WPP_Traceguids_01);
  }
  if ( dword_405AE0 && dword_405AF0 )
  {
    ((void (*)(void))MmUnmapIoSpace)();
    dword_405AE0 = 0;
    dword_405AF0 = 0;
  }
  if ( dword_405B50 && dword_405AE8 )
  {
    ((void (*)(void))MmUnmapIoSpace)();
    dword_405B50 = 0;
    dword_405AE8 = 0;
  }
  if ( !dword_405AE4 )
    return 0;
  v3 = (_DWORD *)dword_405AF4;
  if ( dword_405AF4 )
  {
    for ( i = 0; i < dword_405AE4; v3 = (_DWORD *)dword_405AF4 )
      MmUnmapIoSpace(v3[2 * i++ + 1], 4);
    ExFreePoolWithTag(v3, 0);
    dword_405AF4 = 0;
    dword_405AE4 = 0;
  }
  return 0;
}


// Function: EvtWdfDeviceFileCreate
void __fastcall EvtWdfDeviceFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
  unsigned __int64 v4; // r0

  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
  {
    LODWORD(v4) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v4) = *((_DWORD *)off_405130 + 5);
    DoTraceMessage_01(v4, 0x1Du, &WPP_Traceguids_01);
  }
  WdfFunctions.WdfRequestComplete(WdfDriverGlobals, Request, 0);
}


// Function: EvtWdfIoQueueIoInternalDeviceControl
void __fastcall EvtWdfIoQueueIoInternalDeviceControl(
        WDFQUEUE Queue,
        WDFREQUEST Request,
        size_t OutputBufferLength,
        size_t InputBufferLength,
        ULONG IoControlCode)
{
  unsigned int v6; // r3
  unsigned __int64 v7; // r0
  unsigned __int64 v8; // r0
  NTSTATUS v9; // r4
  _DWORD *v10; // r1
  unsigned __int16 v11; // r2
  unsigned __int64 v12; // r0
  NTSTATUS v13; // lr
  int v14; // r2
  int *v15; // r1
  int v16; // t1
  unsigned __int64 v17; // r0
  int v18; // r0
  _DWORD *v19; // [sp+8h] [bp-28h] BYREF
  _DWORD *v20; // [sp+Ch] [bp-24h] BYREF
  int v21; // [sp+10h] [bp-20h] BYREF

  if ( IoControlCode == 0x42000 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
    {
      LODWORD(v17) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v17) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v17, 0x1Eu, &WPP_Traceguids_01);
    }
    v9 = ((int (__fastcall *)(int, WDFREQUEST, int, _DWORD **, _DWORD))WdfFunctions.WdfRequestRetrieveOutputBuffer)(
           WdfDriverGlobals,
           Request,
           52,
           &v19,
           0);
    if ( v9 >= 0 )
    {
      v18 = WdfDriverGlobals;
      *v19 = smem_alloc;
      v19[1] = smem_get_addr;
      v19[2] = nullsub_1;
      v19[3] = smem_version_set;
      v19[4] = smem_spin_lock;
      v19[5] = smem_spin_unlock;
      v19[6] = sub_4027A8;
      v19[7] = sub_40253C;
      v19[8] = sub_4025D0;
      v19[9] = sub_402698;
      v19[10] = sub_402A74;
      v19[11] = sub_401D8C;
      v19[12] = sub_401D3C;
      WdfFunctions.WdfRequestCompleteWithInformation(v18, Request, v9, (ULONG *)52);
      return;
    }
    v10 = off_405130;
    if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
    {
LABEL_34:
      WdfFunctions.WdfRequestComplete(WdfDriverGlobals, Request, v9);
      return;
    }
    v11 = 31;
    goto LABEL_32;
  }
  if ( IoControlCode != 270340 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
    {
      v6 = *((unsigned __int8 *)off_405130 + 29);
      if ( v6 >= 2 )
      {
        HIDWORD(v7) = *((_DWORD *)off_405130 + 5);
        LODWORD(v7) = *((_DWORD *)off_405130 + 4);
        DoTraceMessage_02(v7, 0x23u, v6, IoControlCode);
      }
    }
    WdfFunctions.WdfRequestComplete(WdfDriverGlobals, Request, STATUS_NOT_SUPPORTED);
    return;
  }
  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((unsigned __int8 *)off_405130 + 29) >= 4u )
  {
    LODWORD(v8) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v8) = *((_DWORD *)off_405130 + 5);
    DoTraceMessage_01(v8, 0x20u, &WPP_Traceguids_01);
  }
  v9 = WdfFunctions.WdfRequestRetrieveInputBuffer(WdfDriverGlobals, Request, 8, (PVOID *)&v20, 0);
  if ( v9 < 0 )
  {
    v10 = off_405130;
    if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
      goto LABEL_34;
    v11 = 33;
LABEL_32:
    LODWORD(v12) = v10[4];
    HIDWORD(v12) = v10[5];
LABEL_33:
    DoTraceMessage_04(v12, v11, &WPP_Traceguids_01, v9);
    goto LABEL_34;
  }
  v9 = ((int (__fastcall *)(int, WDFREQUEST, int, int *, _DWORD))WdfFunctions.WdfRequestRetrieveOutputBuffer)(
         WdfDriverGlobals,
         Request,
         8,
         &v21,
         0);
  if ( v9 < 0 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) == 0 || *((unsigned __int8 *)off_405130 + 29) < 2u )
      goto LABEL_34;
    LODWORD(v12) = *((_DWORD *)off_405130 + 4);
    HIDWORD(v12) = *((_DWORD *)off_405130 + 5);
    v11 = 34;
    goto LABEL_33;
  }
  v13 = -1073741275;
  v14 = 0;
  if ( dword_405AE4 > 0 )
  {
    v15 = (int *)dword_405AF4;
    while ( 1 )
    {
      v16 = *v15;
      v15 += 2;
      if ( *v20 == v16 )
        break;
      if ( ++v14 >= dword_405AE4 )
      {
        WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, -1073741275, (ULONG *)8);
        return;
      }
    }
    v13 = 0;
    *(_DWORD *)(v21 + 4) = *(_DWORD *)(dword_405AF4 + 8 * v14 + 4);
  }
  WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, v13, (ULONG *)8);
}


// Function: EvtWdfDeviceSurpriseRemoval
void __fastcall __noreturn EvtWdfDeviceSurpriseRemoval(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_405130 + 8) & 1) != 0 )
  {
    v1 = *((unsigned __int8 *)off_405130 + 29);
    if ( v1 >= 4 )
    {
      HIDWORD(v2) = *((_DWORD *)off_405130 + 5);
      LODWORD(v2) = *((_DWORD *)off_405130 + 4);
      DoTraceMessage_02(v2, 0x24u, v1, Device);
    }
  }
  KeBugCheckEx(0x14Eu, (ULONG *)0x30657371, 0, 0, 0);
}


// Function: sub_401D3C
// This is a simple accessor function that returns the size of the main shared memory region. This is a useful utility for other parts of the driver or for other drivers that need to know the size of the shared memory buffer they are working with.
int sub_401D3C()
{
  int result; // r0
  unsigned __int64 v1; // r0

  result = dword_405AF0;
  if ( !dword_405AF0 && (*((_DWORD *)off_405130 + 8) & 2) != 0 )
  {
    if ( *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v1) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v1) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v1, 0x26u, &WPP_Traceguids_01);
      return dword_405AF0;
    }
  }
  return result;
}


// Function: sub_401D8C
// This is a specialized write function that writes a single 32-bit value to a shared memory buffer. It's a convenient wrapper around the more general-purpose sub_40253C (the memory write function), and it's likely used for setting status flags, counters, or other small data items in the shared memory.
int sub_401D8C()
{
  unsigned __int64 v0; // r0

  if ( dword_405AF0 )
    return dword_405AEC;
  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
  {
    if ( *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v0) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v0) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v0, 0x27u, &WPP_Traceguids_01);
    }
  }
  return dword_405AEC;
}


// Function: DoTraceMessage_08
int DoTraceMessage_08(unsigned __int64 a1, int a2, int a3, ...)
{
  int v4; // [sp+40h] [bp+18h] BYREF
  va_list va; // [sp+40h] [bp+18h]
  void *v6; // [sp+44h] [bp+1Ch] BYREF
  va_list va1; // [sp+44h] [bp+1Ch]
  va_list va2; // [sp+48h] [bp+20h] BYREF

  va_start(va2, a3);
  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  va_copy(va2, va1);
  v6 = va_arg(va2, void *);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_02, 0xFu, va, 4, va1, 4, va2, 4, 0);
}


// Function: smem_alloc_equivalent
int __fastcall sub_401E2C(smem_mem_type smem_type, int a2)
{
  int v5; // r2
  unsigned __int64 v6; // r0
  int v7; // r2
  int i; // r3
  int *v9; // r2

  if ( smem_type == SMEM_HW_RESET_DETECT )
  {
    if ( a2 == 8 )
    {
      sub_401F74();
      return dword_405144 + 8400;
    }
    else
    {
      return 0;
    }
  }
  else
  {
    if ( !dword_405144 )
    {
      v5 = dword_405AE0;
      if ( !dword_405AE0 && (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v6) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v6) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_01(v6, 0x25u, &WPP_Traceguids_01);
        v5 = dword_405AE0;
      }
      dword_405144 = v5;
    }
    v7 = 0;
    for ( i = *off_405140; i != 426; i = off_405140[2 * v7] )
    {
      if ( i == smem_type )
        break;
      ++v7;
    }
    v9 = &off_405140[2 * v7];
    if ( *v9 == smem_type && v9[1] == a2 )
      return sub_401EEC(smem_type) + dword_405144;
    else
      return 0;
  }
}


// Function: sub_401EEC
int __fastcall sub_401EEC(int a1)
{
  int v1; // r2
  int v2; // r1
  int v3; // r3
  int *v4; // r5
  int v5; // r3
  unsigned __int64 v6; // r0

  v1 = 0;
  v2 = 0;
  v3 = *off_405140;
  if ( *off_405140 != 426 )
  {
    v4 = off_405140;
    do
    {
      if ( v3 == a1 )
        break;
      v5 = v4[1];
      ++v2;
      v4 = &off_405140[2 * v2];
      v1 += v5;
      v3 = *v4;
    }
    while ( *v4 != 426 );
  }
  if ( dword_4040D0[2 * v2] == a1 )
    return v1;
  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
  {
    if ( *((_BYTE *)off_405130 + 29) )
    {
      HIDWORD(v6) = *((_DWORD *)off_405130 + 5);
      LODWORD(v6) = *((_DWORD *)off_405130 + 4);
      DoTraceMessage_04(v6, 0xAu, &WPP_Traceguids_02);
    }
  }
  return -1;
}


// Function: sub_401F74
int sub_401F74()
{
  int v0; // r2
  unsigned __int64 v1; // r0
  int result; // r0

  if ( !dword_405144 )
  {
    v0 = dword_405AE0;
    if ( !dword_405AE0 && (*((_DWORD *)off_405130 + 8) & 2) != 0 )
    {
      if ( *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v1) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v1) = *((_DWORD *)off_405130 + 5);
        result = DoTraceMessage_01(v1, 0x25u, &WPP_Traceguids_01);
        v0 = dword_405AE0;
      }
    }
    dword_405144 = v0;
  }
  return result;
}


// Function: smem_init
int sub_401FCC()
{
  int v0; // r1
  unsigned __int64 v1; // r0
  int result; // r0
  unsigned __int64 v3; // r0
  int v4; // r4
  _DWORD *v5; // r1
  unsigned __int64 v6; // r0
  unsigned int i; // r3
  unsigned int v8; // r2
  unsigned __int64 v9; // r0

  if ( !dword_405144 )
  {
    v0 = dword_405AE0;
    if ( !dword_405AE0 && (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v1) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v1) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v1, 0x25u, &WPP_Traceguids_01);
      v0 = dword_405AE0;
    }
    dword_405144 = v0;
  }
  dword_40513C = dword_405144 + sub_401EEC(2);
  dword_405138 = dword_405144 + sub_401EEC(1);
  result = sub_401EEC(8);
  dword_405148 = dword_405144 + result;
  if ( *(_DWORD *)dword_405138 == 1 )
  {
    dword_405B00 = dword_405144 + sub_401EEC(7);
    dword_405B04 = 8;
    KeInitializeSpinLock(&dword_405AF8);
    __dmb(0xFu);
    unk_40514C = 3;                             // smem_info.state = SMEM_STATE_INITIALIZED
    v4 = 1;
    result = smem_alloc_equivalent(3, 128);
    if ( result )
    {
      *(_DWORD *)(result + 32) |= 0xB0000u;     // 0xB0000 = SMEM_LEGACY_VERSION_ID
      __dmb(0xFu);
      for ( i = 0; i < 0x20; ++i )
      {
        v8 = *(_DWORD *)(result + 4 * i) & 0xFFFF0000;
        if ( v8 && v8 != 720896 )
        {
          v4 = 0;
          i = 32;
        }
      }
      v5 = off_405130;
    }
    else
    {
      v5 = off_405130;
      if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v6) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v6) = *((_DWORD *)off_405130 + 5);
        result = DoTraceMessage_04(v6, 0x11u, &WPP_Traceguids_02);
        v5 = off_405130;
      }
      v4 = 0;
    }
    if ( !v4 && (v5[8] & 2) != 0 && *((_BYTE *)v5 + 29) )
    {
      LODWORD(v9) = v5[4];
      HIDWORD(v9) = v5[5];
      return DoTraceMessage_04(v9, 0xCu, &WPP_Traceguids_02);
    }
  }
  else if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
  {
    if ( *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v3) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v3) = *((_DWORD *)off_405130 + 5);
      return DoTraceMessage_01(v3, 0xBu, &WPP_Traceguids_02);
    }
  }
  return result;
}


// Function: smem_alloc
// This function is a custom memory allocator that manages multiple heaps. It allows the driver to allocate memory from different pools, creating new heaps on demand if a requested pool doesn't exist.
void *__fastcall smem_alloc(smem_mem_type smem_type, int buf_size)
{
  unsigned __int64 v5; // r0
  unsigned int v6; // r9
  void *v7; // r2
  unsigned __int64 v8; // r0
  int v9; // r3
  __int32 v10; // r0
  void *v11; // r5
  _DWORD *v12; // r1
  unsigned __int64 v13; // r0
  unsigned int v14; // lr
  int v15; // r1
  unsigned __int64 v16; // r0
  unsigned __int64 v17; // r0

  if ( unk_40514C == 1 )
    return 0;
  if ( (unsigned int)smem_type <= SMEM_MEMORY_BARRIER_LOCATION )
    return (void *)smem_alloc_equivalent(smem_type, buf_size);
  if ( !unk_40514C )
    smem_init(smem_type);
  if ( (unsigned int)smem_type > SMEM_SSR_REASON_VCODEC0 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
    {
      if ( *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v5) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v5) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_04(v5, 0xDu, &WPP_Traceguids_02, smem_type);
      }
    }
    return 0;
  }
  v6 = (buf_size + 7) & 0xFFFFFFF8;
  if ( dword_405B04 > 3 )
  {
    byte_405AFC = KeAcquireSpinLockRaiseToDpc(&dword_405AF8);
    do
    {
      v9 = dword_405B50;
      *(_DWORD *)(dword_405B50 + 12) = 0;
    }
    while ( *(_DWORD *)(v9 + 12) );
  }
  else
  {
    v7 = off_405130;
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v8) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v8) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v8, 0xAu, &stru_404168);
    }
  }
  v10 = 16 * smem_type;
  if ( *(_DWORD *)(16 * smem_type + dword_40513C) == 1 )
  {
    if ( v6 == *(_DWORD *)(dword_40513C + v10 + 8) )
    {
      v11 = (void *)(*(_DWORD *)(dword_40513C + v10 + 4) + dword_405144);
LABEL_28:
      v12 = off_405130;
      goto LABEL_29;
    }
    v11 = 0;
    v12 = off_405130;
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v13) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v13) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_04(v13, 0xEu, &WPP_Traceguids_02, smem_type);
      goto LABEL_28;
    }
  }
  else
  {
    v14 = *(_DWORD *)(dword_405138 + 8);
    if ( v6 <= v14 )
    {
      v15 = *(_DWORD *)(dword_405138 + 4);
      *(_DWORD *)(dword_405138 + 4) = v15 + v6;
      *(_DWORD *)(dword_405138 + 8) = v14 - v6;
      *(_DWORD *)(dword_40513C + v10 + 4) = v15;
      *(_DWORD *)(dword_40513C + v10 + 8) = v6;
      *(_DWORD *)(v10 + dword_40513C) = 1;
      v11 = (void *)(dword_405144 + v15);
      __dmb(0xFu);
      goto LABEL_28;
    }
    v11 = 0;
    v12 = off_405130;
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v16) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v16) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_08(v16, (int)v7, *((unsigned __int8 *)off_405130 + 29), v14, v6, smem_type);
      goto LABEL_28;
    }
  }
LABEL_29:
  if ( dword_405B04 > 3 )
  {
    *(_DWORD *)(dword_405B50 + 12) = 0;
    KeReleaseSpinLock(&dword_405AF8, byte_405AFC);
  }
  else if ( (v12[8] & 2) != 0 && *((_BYTE *)v12 + 29) )
  {
    LODWORD(v17) = v12[4];
    HIDWORD(v17) = v12[5];
    DoTraceMessage_01(v17, 0xBu, &stru_404168);
    return v11;
  }
  return v11;
}


// Function: smem_get_addr
// Request a pointer to an already allocated buffer in shared memory. Returns the address and size of the allocated buffer.
// 
// Newly-allocated shared memory buffers, which have never been
// allocated on any processor, are guaranteed to be zeroed.
// 
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/main/boot_images/QcomPkg/Library/SmemLib/src/smem.c#L188
int __fastcall smem_get_addr(smem_mem_type smem_type, _DWORD *a2)
{
  unsigned int v4; // r2
  int *v5; // r4
  int v6; // t1
  int *v7; // r2
  unsigned __int64 v9; // r0
  unsigned __int64 v10; // r0
  int v11; // r3
  __int32 v12; // r2
  unsigned int v13; // r4
  unsigned __int64 v14; // r0
  unsigned int v15; // r2

  if ( (unsigned int)smem_type > SMEM_MEMORY_BARRIER_LOCATION )
  {
    if ( !unk_40514C )                          // smem_info.state
      smem_init();
    if ( (unsigned int)smem_type <= SMEM_SSR_REASON_VCODEC0 )
    {
      if ( dword_405B04 > 3 )
      {
        byte_405AFC = KeAcquireSpinLockRaiseToDpc(&dword_405AF8);
        do
        {
          v11 = dword_405B50;
          *(_DWORD *)(dword_405B50 + 12) = 0;
        }
        while ( *(_DWORD *)(v11 + 12) );
      }
      else if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v10) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v10) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_01(v10, 0xAu, &stru_404168);
      }
      v12 = 16 * smem_type;
      if ( *(_DWORD *)(16 * smem_type + dword_40513C) == 1 )
      {
        *a2 = *(_DWORD *)(dword_40513C + v12 + 8);
        v13 = *(_DWORD *)(dword_40513C + v12 + 4) + dword_405144;
      }
      else
      {
        *a2 = 0;
        v13 = 0;
      }
      if ( dword_405B04 > 3 )
      {
        *(_DWORD *)(dword_405B50 + 12) = 0;
        KeReleaseSpinLock(&dword_405AF8, byte_405AFC);
      }
      else if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v14) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v14) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_01(v14, 0xBu, &stru_404168);
      }
      if ( v13 )
      {
        v15 = sub_401D3C() + dword_405144;
        if ( v13 < dword_405144 || v13 >= v15 || *a2 + v13 >= v15 )
        {
          *a2 = 0;
          return 0;
        }
      }
      return v13;
    }
    else
    {
      if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v9) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v9) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_04(v9, 0x10u, &WPP_Traceguids_02);
      }
      return 0;
    }
  }
  else
  {
    v4 = 0;
    v5 = off_405140;
    do
    {
      v6 = *v5;
      v5 += 2;
      if ( v6 == smem_type )
        break;
      ++v4;
    }
    while ( v4 <= 8 );
    v7 = &off_405140[2 * v4];
    *a2 = v7[1];
    return smem_alloc_equivalent(smem_type, v7[1]);
  }
}


// Function: nullsub_1
// This is a null subroutine. It performs no operations and returns immediately. It is likely used as a placeholder or for a callback that doesn't need to do anything.
void nullsub_1()
{
  ;
}


// Function: smem_version_set
// This function is used to negotiate or assert a version number for a shared memory interface. It ensures that the component using this driver is compatible with the driver's version of the shared memory layout.
BOOLEAN __fastcall smem_version_set(smem_mem_type type, int version, int mask)
{
  BOOLEAN match; // r4
  _DWORD *version_array; // r0
  unsigned __int64 v8; // r0
  unsigned int i; // r2

  match = 1;
  if ( type != SMEM_VERSION_INFO && (type < SMEM_VERSION_FIRST || type > SMEM_VERSION_LAST) )
    return 0;
  version_array = smem_alloc(type, 128);        // 128 = SMEM_VERSION_INFO_SIZE * sizeof(uint32)
  if ( !version_array )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
    {
      if ( *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v8) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v8) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_04(v8, 0x11u, &WPP_Traceguids_02);
      }
    }
    return 0;
  }
  version_array[8] |= version & mask;           // 8=SMEM_VERSION_INFO_OFFSET
  __dmb(0xFu);
  for ( i = 0; i < 32; ++i )                    // 32 = SMEM_VERSION_INFO_SIZE
  {
    if ( (version_array[i] & mask) != 0 && (version_array[i] & mask) != (version & mask) )
    {
      match = 0;                                // False
      i = 32;
    }
  }
  return match;
}


// Function: sub_40253C
// This function is for writing data to a specific shared memory buffer. It uses smem_alloc to get a pointer to the buffer, performs a bounds check, and then copies the data. This function, along with sub_4027A8, provides the read/write interface to the shared memory regions managed by this driver.
int __fastcall sub_40253C(unsigned int a1)
{
  int *v1; // r4
  smem_mem_type v2; // r0
  unsigned __int64 v4; // r0

  if ( a1 > 1 )
    return -1;
  v1 = &dword_405150[12 * a1];
  v1[7] = (int)smem_alloc((smem_mem_type)v1[3], 20 * v1[2]);
  v1[8] = (int)smem_alloc((smem_mem_type)v1[4], 4);
  v2 = v1[5];
  if ( v2 != SMEM_VOICE )
    v1[9] = (int)smem_alloc(v2, 4);
  if ( v1[7] && v1[8] )
    return 0;
  if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
  {
    if ( *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v4) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v4) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_01(v4, 0xAu, &stru_404158);
    }
  }
  return -1;
}


// Function: sub_4025D0
// This utility function retrieves the size of a previously allocated shared memory buffer. It uses RtlSizeHeap to get the exact size of the allocation, which is a reliable way to determine the buffer's capacity.
void __fastcall sub_4025D0(unsigned int a1, int a2, int a3, int a4, int a5, int a6)
{
  int *v8; // r5
  unsigned __int64 InterruptTime; // r0
  int v10; // r8
  unsigned int v11; // r4
  unsigned int v12; // r1
  _DWORD *v13; // r3

  if ( a1 <= 1 )
  {
    v8 = &dword_405150[12 * a1];
    if ( v8[8] )
    {
      InterruptTime = KeQueryInterruptTime();
      v10 = _rt_udiv64(10000000, 0, (_DWORD)InterruptTime << 15, InterruptTime >> 17);
      smem_spin_lock(v8[6]);
      v11 = *(_DWORD *)v8[8];
      v12 = v11 + 1;
      if ( v11 + 1 >= v8[2] )
      {
        v13 = (_DWORD *)v8[9];
        v12 = 0;
        if ( v13 )
          *(_DWORD *)v8[9] = *v13 + 1;
      }
      *(_DWORD *)v8[8] = v12;
      if ( !v8[1] )
        smem_spin_unlock(v8[6]);
      if ( v11 < v8[2] )
      {
        *(_DWORD *)(v8[7] + 20 * v11) = a2 | 0x80000000;
        *(_DWORD *)(v8[7] + 20 * v11 + 4) = v10;
        *(_DWORD *)(v8[7] + 20 * v11 + 8) = a4;
        *(_DWORD *)(v8[7] + 20 * v11 + 12) = a5;
        *(_DWORD *)(v8[7] + 20 * v11 + 16) = a6;
      }
      if ( v8[1] )
        smem_spin_unlock(v8[6]);
    }
  }
}


// Function: sub_402698
// This search function operates on a shared memory buffer. It allows a component to check for the existence of a specific item within the buffer. This could be used for a variety of purposes, such as checking if a particular resource has been initialized or if a certain flag has been set.
void __fastcall sub_402698(unsigned int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9)
{
  int *v11; // r5
  unsigned __int64 InterruptTime; // r0
  int v13; // r8
  unsigned int v14; // r4
  unsigned int v15; // r3
  unsigned int v16; // r1
  _DWORD *v17; // r3
  int v18; // r1
  unsigned int v19; // r4

  if ( a1 <= 1 )
  {
    v11 = &dword_405150[12 * a1];
    if ( v11[8] )
    {
      InterruptTime = KeQueryInterruptTime();
      v13 = _rt_udiv64(10000000, 0, (_DWORD)InterruptTime << 15, InterruptTime >> 17);
      smem_spin_lock(v11[6]);
      v14 = *(_DWORD *)v11[8];
      v15 = v11[2];
      v16 = v14 + 2;
      if ( v14 + 2 >= v15 )
      {
        v16 -= v15;
        v17 = (_DWORD *)v11[9];
        if ( v17 )
          *(_DWORD *)v11[9] = *v17 + 1;
        if ( v16 >= v11[2] )
          v16 = 0;
      }
      *(_DWORD *)v11[8] = v16;
      if ( !v11[1] )
        smem_spin_unlock(v11[6]);
      if ( v14 < v11[2] )
      {
        v18 = 5 * v14;
        *(_DWORD *)(v11[7] + 20 * v14) = a2 | 0x80000000;
        v19 = v14 + 1;
        *(_DWORD *)(v11[7] + 4 * v18 + 4) = v13;
        *(_DWORD *)(v11[7] + 4 * v18 + 8) = a4;
        *(_DWORD *)(v11[7] + 4 * v18 + 12) = a5;
        *(_DWORD *)(v11[7] + 4 * v18 + 16) = a6;
        if ( v19 == v11[2] )
          v19 = 0;
        *(_DWORD *)(v11[7] + 20 * v19) = a2 | 0x90000000;
        *(_DWORD *)(v11[7] + 20 * v19 + 4) = v13;
        *(_DWORD *)(v11[7] + 20 * v19 + 8) = a7;
        *(_DWORD *)(v11[7] + 20 * v19 + 12) = a8;
        *(_DWORD *)(v11[7] + 20 * v19 + 16) = a9;
      }
      if ( v11[1] )
        smem_spin_unlock(v11[6]);
    }
  }
}


// Function: sub_4027A8
// This function is for reading data from a specific shared memory buffer. It uses smem_alloc to get a pointer to the buffer, performs a bounds check, and then copies the data.
int __fastcall sub_4027A8(unsigned int a1, unsigned int a2, char *a3, _DWORD *a4, _DWORD *a5)
{
  int v7; // r10
  int *v8; // r4
  int v10; // r8
  int *v11; // r3
  unsigned int v12; // r2
  unsigned int v13; // r1
  unsigned int v14; // r7
  unsigned int v15; // r5
  unsigned int v16; // r1
  unsigned int v17; // r9
  unsigned __int64 v18; // r0
  int v19; // r0
  int v20; // r1
  int v21; // r3
  int v22; // r8
  int *v23; // r3
  unsigned int v24; // r2
  int v25; // r1
  unsigned int v26; // r2
  unsigned int v27; // r5
  int v29; // [sp+Ch] [bp-2Ch] BYREF
  unsigned int v30; // [sp+10h] [bp-28h]
  unsigned int v31; // [sp+14h] [bp-24h]

  v30 = a2;
  v7 = 0;
  v31 = a1;
  if ( a4 )
    *a4 = 0;
  if ( a5 )
    *a5 = 0;
  if ( a1 > 1 )
    return -1;
  v8 = &dword_405150[12 * a1];
  if ( !v8[1] || !v8[8] )
    return -1;
  if ( !a2 )
    return 0;
  if ( !a3 )
    return -1;
  smem_spin_lock(v8[6]);
  v10 = *(_DWORD *)v8[8];
  v11 = (int *)v8[9];
  if ( v11 )
    v7 = *v11;
  smem_spin_unlock(v8[6]);
  v12 = v8[2];
  v13 = v10 + v12 * v7;
  v14 = v8[10] + v8[11] * v12;
  if ( v13 == v14 )
    return 0;
  if ( v13 >= v14 )
  {
    if ( v13 <= v12 + v14 )
    {
      v10 = v8[10];
      v15 = v13 - v14;
    }
    else
    {
      v15 = v8[2];
      if ( a4 )
        *a4 = v13 - v12 - v14;
      v12 = v8[2];
      v8[10] = v10;
      v14 = v13 - v12;
      v8[11] = v7 - 1;
    }
    if ( v15 <= v12 )
      goto LABEL_16;
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v18) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v18) = *((_DWORD *)off_405130 + 5);
      DoTraceMessage_05(v18, 0xBu, &stru_404158, v15, v12);
    }
    return -1;
  }
  v15 = v8[2];
  v14 = v13 - v12;
LABEL_16:
  if ( v15 > a2 )
    v15 = a2;
  if ( v15 + v10 <= v12 )
  {
    v16 = v15;
    v17 = 0;
  }
  else
  {
    v16 = v12 - v10;
    v17 = v15 + v10 - v12;
  }
  v19 = 5 * v16;
  v20 = v8[7] + 20 * v10;
  v29 = v19;
  _memcpy_forward_new(a3, v20, 4 * v19);
  if ( v17 )
  {
    _memcpy_forward_new(&a3[4 * v29], v8[7], 20 * v17);
    v21 = v8[11];
    v8[10] = v17;
    v8[11] = v21 + 1;
  }
  else
  {
    v8[10] += v15;
  }
  smem_spin_lock(v8[6]);
  v22 = *(_DWORD *)v8[8];
  v23 = (int *)v8[9];
  if ( v23 )
    v7 = *v23;
  smem_spin_unlock(v8[6]);
  v24 = v22 + v8[2] * v7;
  if ( a5 )
    *a5 = v24 - v15 - v14;
  v25 = v8[2];
  if ( v24 > v25 + v14 )
  {
    v29 = 0;
    v26 = v24 - v25 - v14;
    v27 = v15 - v26;
    if ( a4 )
      *a4 += v26;
    memmove(a3, &a3[20 * v26], 20 * v27);
    v15 = v27 + sub_4027A8(v31, v30 - v27, (int)&a3[20 * v27], (int)&v29, (int)a5);
    if ( a4 )
      *a4 += v29;
  }
  return v15;
}


// Function: smem_spin_lock
// Acquires a spinlock as indicated by input integer, protected by non-preemtable critical section (effectively locking interrupts).
int __fastcall sub_402994(int result)
{
  int v1; // r4
  int v2; // r3
  unsigned __int64 v3; // r0

  v1 = result;
  if ( result < 0 || result >= dword_405B04 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 && *((_BYTE *)off_405130 + 29) )
    {
      LODWORD(v3) = *((_DWORD *)off_405130 + 4);
      HIDWORD(v3) = *((_DWORD *)off_405130 + 5);
      return DoTraceMessage_01(v3, 0xAu, &stru_404168);
    }
  }
  else
  {
    result = KeAcquireSpinLockRaiseToDpc(&dword_405AF8);
    byte_405AFC = result;
    do
    {
      v2 = dword_405B50;
      *(_DWORD *)(dword_405B50 + 4 * v1) = 0;
    }
    while ( *(_DWORD *)(v2 + 4 * v1) );
  }
  return result;
}


// Function: smem_spin_unlock
// Releases a spin lock as indicated by input integer, protected by non-preemtable critical section (effectively unlocking interrupts).
void __fastcall sub_402A10(int a1)
{
  unsigned __int64 v1; // r0

  if ( a1 < 0 || a1 >= dword_405B04 )
  {
    if ( (*((_DWORD *)off_405130 + 8) & 2) != 0 )
    {
      if ( *((_BYTE *)off_405130 + 29) )
      {
        LODWORD(v1) = *((_DWORD *)off_405130 + 4);
        HIDWORD(v1) = *((_DWORD *)off_405130 + 5);
        DoTraceMessage_01(v1, 0xBu, &stru_404168);
      }
    }
  }
  else
  {
    *(_DWORD *)(dword_405B50 + 4 * a1) = 0;
    KeReleaseSpinLock(&dword_405AF8, byte_405AFC);
  }
}


// Function: sub_402A74
// This is a specialized read function that retrieves a single 32-bit value from a shared memory buffer. It's a convenient wrapper around the more general-purpose sub_4027A8 (the memory read function), and it's likely used for reading status flags, counters, or other small data items from the shared memory.
void __fastcall sub_402A74(int a1)
{
  KIRQL v2; // r0
  int v3; // r2
  int v4; // r1
  int v5; // r3

  v2 = KeAcquireSpinLockRaiseToDpc(&dword_405AF8);
  v3 = 0;
  byte_405AFC = v2;
  if ( dword_405B04 > 0 )
  {
    v4 = dword_405B50;
    do
    {
      v5 = *(_DWORD *)(v4 + 4 * v3);
      v4 = dword_405B50;
      if ( a1 == v5 )
        *(_DWORD *)(dword_405B50 + 4 * v3) = 0;
      ++v3;
    }
    while ( v3 < dword_405B04 );
    v2 = byte_405AFC;
  }
  KeReleaseSpinLock(&dword_405AF8, v2);
}


// Function: _security_check_cookie
void __fastcall security_check_cookie()
{
  ;
}


// Function: _gsfailure
void __fastcall __noreturn gsfailure(unsigned int a1)
{
  report_gsfailure(a1);
}


// Function: _report_gsfailure
void __fastcall __noreturn report_gsfailure(unsigned int StackCookie)
{
  KeBugCheckEx(0xF7u, (ULONG *)StackCookie, (ULONG *)_security_cookie, (ULONG *)security_cookie_complement, 0);
}


// Function: __memcpy_forward_new
int __fastcall _memcpy_forward_new(int result, unsigned int a2, int a3)
{
  __int16 v3; // r2
  char v4; // r1
  int v5; // r2
  char v6; // r1
  int v7; // r2
  __int16 v8; // r1
  int v9; // r12
  __int16 v10; // r2
  char v11; // r1
  int v12; // r2
  int v13; // r1
  int v14; // r12
  int v15; // r2
  char v16; // r1
  int v17; // r12
  int v18; // r2
  __int16 v19; // r1
  int v20; // r2
  char v21; // r1
  int v22; // r12
  int v23; // r2
  int v24; // r1
  int v25; // r2
  int v26; // r2
  char v27; // r1
  int v28; // r2
  int v29; // r2
  __int16 v30; // r1
  int v31; // r2
  int v32; // r12
  char v33; // r1

  __pld((void *)a2);
  switch ( a3 )
  {
    case 0:
      return result;
    case 1:
      *(_BYTE *)result = *(_BYTE *)a2;
      break;
    case 2:
      *(_WORD *)result = *(_WORD *)a2;
      break;
    case 3:
      v3 = *(_WORD *)a2;
      v4 = *(_BYTE *)(a2 + 2);
      *(_WORD *)result = v3;
      *(_BYTE *)(result + 2) = v4;
      break;
    case 4:
      *(_DWORD *)result = *(_DWORD *)a2;
      break;
    case 5:
      v5 = *(_DWORD *)a2;
      v6 = *(_BYTE *)(a2 + 4);
      *(_DWORD *)result = v5;
      *(_BYTE *)(result + 4) = v6;
      break;
    case 6:
      v7 = *(_DWORD *)a2;
      v8 = *(_WORD *)(a2 + 4);
      *(_DWORD *)result = v7;
      *(_WORD *)(result + 4) = v8;
      break;
    case 7:
      v9 = *(_DWORD *)a2;
      v10 = *(_WORD *)(a2 + 4);
      v11 = *(_BYTE *)(a2 + 6);
      *(_DWORD *)result = v9;
      *(_WORD *)(result + 4) = v10;
      *(_BYTE *)(result + 6) = v11;
      break;
    case 8:
      v12 = *(_DWORD *)a2;
      v13 = *(_DWORD *)(a2 + 4);
      *(_DWORD *)result = v12;
      *(_DWORD *)(result + 4) = v13;
      break;
    case 9:
      v14 = *(_DWORD *)a2;
      v15 = *(_DWORD *)(a2 + 4);
      v16 = *(_BYTE *)(a2 + 8);
      *(_DWORD *)result = v14;
      *(_DWORD *)(result + 4) = v15;
      *(_BYTE *)(result + 8) = v16;
      break;
    case 10:
      v17 = *(_DWORD *)a2;
      v18 = *(_DWORD *)(a2 + 4);
      v19 = *(_WORD *)(a2 + 8);
      *(_DWORD *)result = v17;
      *(_DWORD *)(result + 4) = v18;
      *(_WORD *)(result + 8) = v19;
      break;
    case 11:
      v20 = *(_DWORD *)(a2 + 4);
      *(_DWORD *)result = *(_DWORD *)a2;
      *(_DWORD *)(result + 4) = v20;
      LOWORD(v20) = *(_WORD *)(a2 + 8);
      v21 = *(_BYTE *)(a2 + 10);
      *(_WORD *)(result + 8) = v20;
      *(_BYTE *)(result + 10) = v21;
      break;
    case 12:
      v22 = *(_DWORD *)a2;
      v23 = *(_DWORD *)(a2 + 4);
      v24 = *(_DWORD *)(a2 + 8);
      *(_DWORD *)result = v22;
      *(_DWORD *)(result + 4) = v23;
      *(_DWORD *)(result + 8) = v24;
      break;
    case 13:
      v25 = *(_DWORD *)(a2 + 4);
      *(_DWORD *)result = *(_DWORD *)a2;
      *(_DWORD *)(result + 4) = v25;
      v26 = *(_DWORD *)(a2 + 8);
      v27 = *(_BYTE *)(a2 + 12);
      *(_DWORD *)(result + 8) = v26;
      *(_BYTE *)(result + 12) = v27;
      break;
    case 14:
      v28 = *(_DWORD *)(a2 + 4);
      *(_DWORD *)result = *(_DWORD *)a2;
      *(_DWORD *)(result + 4) = v28;
      v29 = *(_DWORD *)(a2 + 8);
      v30 = *(_WORD *)(a2 + 12);
      *(_DWORD *)(result + 8) = v29;
      *(_WORD *)(result + 12) = v30;
      break;
    case 15:
      v31 = *(_DWORD *)(a2 + 4);
      *(_DWORD *)result = *(_DWORD *)a2;
      *(_DWORD *)(result + 4) = v31;
      v32 = *(_DWORD *)(a2 + 8);
      LOWORD(v31) = *(_WORD *)(a2 + 12);
      v33 = *(_BYTE *)(a2 + 14);
      *(_DWORD *)(result + 8) = v32;
      *(_WORD *)(result + 12) = v31;
      *(_BYTE *)(result + 14) = v33;
      break;
    default:
      if ( ((result ^ a2) & 3) != 0 )
        result = _memcpy_forward_large_neon();
      else
        result = off_405108();
      break;
  }
  return result;
}


// Function: __memcpy_forward_large_integer
void __fastcall _memcpy_forward_large_integer(int a1, char *a2, unsigned int a3, _BYTE *a4)
{
  bool v4; // cf
  char v5; // t1
  __int16 v6; // t1
  unsigned int v7; // r2
  int v8; // r4
  int v9; // r5
  int v10; // r6
  int v11; // r7
  int v12; // r8
  int v13; // r9
  int v14; // r12
  int v15; // lr
  int v16; // r4
  int v17; // r5
  int v18; // r6
  int v19; // r7
  int v20; // r8
  int v21; // r9
  int v22; // r12
  int v23; // lr
  unsigned int i; // r2
  __int64 v25; // t1
  unsigned int v26; // r2
  int v27; // r4
  int v28; // r5
  int v29; // r6
  int v30; // r7
  int v31; // r8
  int v32; // r9
  int v33; // r12
  int v34; // lr
  unsigned int j; // r2
  __int64 v36; // r4

  v4 = __CFSHL__(a4, 31);
  if ( ((unsigned __int8)a4 & 1) != 0 )
  {
    v5 = *a2++;
    --a3;
    *a4++ = v5;
    v4 = __CFSHL__(a4, 31);
  }
  if ( v4 )
  {
    v6 = *(_WORD *)a2;
    a2 += 2;
    a3 -= 2;
    *(_WORD *)a4 = v6;
    a4 += 2;
  }
  if ( ((unsigned __int8)a2 & 3) == 0 )
  {
    v4 = a3 >= 0x20;
    v7 = a3 - 32;
    if ( v4 )
    {
      v4 = v7 >= 0x20;
      v7 -= 32;
      __pld(a2 + 32);
      for ( ; v4; a4 += 32 )
      {
        __pld(a2 + 64);
        v4 = v7 >= 0x20;
        v7 -= 32;
        v8 = *(_DWORD *)a2;
        v9 = *((_DWORD *)a2 + 1);
        v10 = *((_DWORD *)a2 + 2);
        v11 = *((_DWORD *)a2 + 3);
        v12 = *((_DWORD *)a2 + 4);
        v13 = *((_DWORD *)a2 + 5);
        v14 = *((_DWORD *)a2 + 6);
        v15 = *((_DWORD *)a2 + 7);
        a2 += 32;
        *(_DWORD *)a4 = v8;
        *((_DWORD *)a4 + 1) = v9;
        *((_DWORD *)a4 + 2) = v10;
        *((_DWORD *)a4 + 3) = v11;
        *((_DWORD *)a4 + 4) = v12;
        *((_DWORD *)a4 + 5) = v13;
        *((_DWORD *)a4 + 6) = v14;
        *((_DWORD *)a4 + 7) = v15;
      }
      v16 = *(_DWORD *)a2;
      v17 = *((_DWORD *)a2 + 1);
      v18 = *((_DWORD *)a2 + 2);
      v19 = *((_DWORD *)a2 + 3);
      v20 = *((_DWORD *)a2 + 4);
      v21 = *((_DWORD *)a2 + 5);
      v22 = *((_DWORD *)a2 + 6);
      v23 = *((_DWORD *)a2 + 7);
      a2 += 32;
      *(_DWORD *)a4 = v16;
      *((_DWORD *)a4 + 1) = v17;
      *((_DWORD *)a4 + 2) = v18;
      *((_DWORD *)a4 + 3) = v19;
      *((_DWORD *)a4 + 4) = v20;
      *((_DWORD *)a4 + 5) = v21;
      *((_DWORD *)a4 + 6) = v22;
      *((_DWORD *)a4 + 7) = v23;
      a4 += 32;
    }
    v4 = __CFADD__(v7, 24);
    for ( i = v7 + 24; v4; a4 += 8 )
    {
      v4 = i >= 8;
      i -= 8;
      v25 = *(_QWORD *)a2;
      a2 += 8;
      *(_QWORD *)a4 = v25;
    }
    if ( i == -8 )
      return;
LABEL_26:
    JUMPOUT(0x402B6A);
  }
  v4 = a3 >= 0x40;
  v26 = a3 - 64;
  if ( v4 )
  {
    __pld(a2 + 32);
    do
    {
      __pld(a2 + 64);
      v27 = *(_DWORD *)a2;
      v28 = *((_DWORD *)a2 + 1);
      v29 = *((_DWORD *)a2 + 2);
      v30 = *((_DWORD *)a2 + 3);
      v31 = *((_DWORD *)a2 + 4);
      v32 = *((_DWORD *)a2 + 5);
      v33 = *((_DWORD *)a2 + 6);
      v34 = *((_DWORD *)a2 + 7);
      a2 += 32;
      v4 = v26 >= 0x20;
      v26 -= 32;
      *(_DWORD *)a4 = v27;
      *((_DWORD *)a4 + 1) = v28;
      *((_DWORD *)a4 + 2) = v29;
      *((_DWORD *)a4 + 3) = v30;
      *((_DWORD *)a4 + 4) = v31;
      *((_DWORD *)a4 + 5) = v32;
      *((_DWORD *)a4 + 6) = v33;
      *((_DWORD *)a4 + 7) = v34;
      a4 += 32;
    }
    while ( v4 );
  }
  v4 = __CFADD__(v26, 56);
  for ( j = v26 + 56; v4; a4 += 8 )
  {
    v36 = *(_QWORD *)a2;
    a2 += 8;
    v4 = j >= 8;
    j -= 8;
    *(_QWORD *)a4 = v36;
  }
  if ( j != -8 )
    goto LABEL_26;
}


// Function: __memcpy_forward_large_neon
void __fastcall _memcpy_forward_large_neon(int a1, __int64 *a2, unsigned int a3, int a4)
{
  bool v4; // cf
  unsigned int v5; // r2
  __int64 v6; // d0
  __int64 v7; // d1
  __int64 v8; // d2
  __int64 v9; // d3
  __int64 v10; // d0
  __int64 v11; // d1
  __int64 v12; // d2
  __int64 v13; // d3
  unsigned int i; // r2
  int v15; // r4
  int v16; // r5

  v4 = a3 >= 0x20;
  v5 = a3 - 32;
  if ( v4 )
  {
    v4 = v5 >= 0x20;
    v5 -= 32;
    __pld(a2 + 4);
    for ( ; v4; a4 += 32 )
    {
      __pld(a2 + 8);
      v4 = v5 >= 0x20;
      v5 -= 32;
      v6 = *a2;
      v7 = a2[1];
      v8 = a2[2];
      v9 = a2[3];
      a2 += 4;
      *(_QWORD *)a4 = v6;
      *(_QWORD *)(a4 + 8) = v7;
      *(_QWORD *)(a4 + 16) = v8;
      *(_QWORD *)(a4 + 24) = v9;
    }
    v10 = *a2;
    v11 = a2[1];
    v12 = a2[2];
    v13 = a2[3];
    a2 += 4;
    *(_QWORD *)a4 = v10;
    *(_QWORD *)(a4 + 8) = v11;
    *(_QWORD *)(a4 + 16) = v12;
    *(_QWORD *)(a4 + 24) = v13;
    a4 += 32;
  }
  v4 = __CFADD__(v5, 24);
  for ( i = v5 + 24; v4; i -= 8 )
  {
    v15 = *(_DWORD *)a2;
    v16 = *((_DWORD *)a2++ + 1);
    *(_DWORD *)a4 = v15;
    *(_DWORD *)(a4 + 4) = v16;
    a4 += 8;
    v4 = i >= 8;
  }
  if ( i != -8 )
    JUMPOUT(0x402B6A);
}


// Function: memmove
void *__fastcall memmove(void *dest, const void *src, size_t count)
{
  __int16 v3; // r2
  char v4; // r1
  int v5; // r2
  char v6; // r1
  int v7; // r2
  __int16 v8; // r1
  int v9; // r3
  __int16 v10; // r2
  char v11; // r1
  int v12; // r2
  int v13; // r1
  int v14; // r3
  int v15; // r2
  char v16; // r1
  int v17; // r3
  int v18; // r2
  __int16 v19; // r1
  int v20; // r12
  int v21; // r3
  __int16 v22; // r2
  char v23; // r1
  int v24; // r12
  int v25; // r2
  int v26; // r1
  int v27; // r12
  int v28; // r3
  int v29; // r2
  char v30; // r1
  int v31; // r12
  int v32; // r3
  int v33; // r2
  __int16 v34; // r1
  char v35; // r2
  int v36; // r3
  int v37; // r2
  int v38; // r1

  if ( (_BYTE *)dest - (_BYTE *)src >= count )
    return (void *)_memcpy_forward_new((int)dest, (unsigned int)src, count);
  __pld((void *)src);
  switch ( count )
  {
    case 0u:
      return dest;
    case 1u:
      *(_BYTE *)dest = *(_BYTE *)src;
      break;
    case 2u:
      *(_WORD *)dest = *(_WORD *)src;
      break;
    case 3u:
      v3 = *(_WORD *)src;
      v4 = *((_BYTE *)src + 2);
      *(_WORD *)dest = v3;
      *((_BYTE *)dest + 2) = v4;
      break;
    case 4u:
      *(_DWORD *)dest = *(_DWORD *)src;
      break;
    case 5u:
      v5 = *(_DWORD *)src;
      v6 = *((_BYTE *)src + 4);
      *(_DWORD *)dest = v5;
      *((_BYTE *)dest + 4) = v6;
      break;
    case 6u:
      v7 = *(_DWORD *)src;
      v8 = *((_WORD *)src + 2);
      *(_DWORD *)dest = v7;
      *((_WORD *)dest + 2) = v8;
      break;
    case 7u:
      v9 = *(_DWORD *)src;
      v10 = *((_WORD *)src + 2);
      v11 = *((_BYTE *)src + 6);
      *(_DWORD *)dest = v9;
      *((_WORD *)dest + 2) = v10;
      *((_BYTE *)dest + 6) = v11;
      break;
    case 8u:
      v12 = *(_DWORD *)src;
      v13 = *((_DWORD *)src + 1);
      *(_DWORD *)dest = v12;
      *((_DWORD *)dest + 1) = v13;
      break;
    case 9u:
      v14 = *(_DWORD *)src;
      v15 = *((_DWORD *)src + 1);
      v16 = *((_BYTE *)src + 8);
      *(_DWORD *)dest = v14;
      *((_DWORD *)dest + 1) = v15;
      *((_BYTE *)dest + 8) = v16;
      break;
    case 0xAu:
      v17 = *(_DWORD *)src;
      v18 = *((_DWORD *)src + 1);
      v19 = *((_WORD *)src + 4);
      *(_DWORD *)dest = v17;
      *((_DWORD *)dest + 1) = v18;
      *((_WORD *)dest + 4) = v19;
      break;
    case 0xBu:
      v20 = *(_DWORD *)src;
      v21 = *((_DWORD *)src + 1);
      v22 = *((_WORD *)src + 4);
      v23 = *((_BYTE *)src + 10);
      *(_DWORD *)dest = v20;
      *((_DWORD *)dest + 1) = v21;
      *((_WORD *)dest + 4) = v22;
      *((_BYTE *)dest + 10) = v23;
      break;
    case 0xCu:
      v24 = *(_DWORD *)src;
      v25 = *((_DWORD *)src + 1);
      v26 = *((_DWORD *)src + 2);
      *(_DWORD *)dest = v24;
      *((_DWORD *)dest + 1) = v25;
      *((_DWORD *)dest + 2) = v26;
      break;
    case 0xDu:
      v27 = *(_DWORD *)src;
      v28 = *((_DWORD *)src + 1);
      v29 = *((_DWORD *)src + 2);
      v30 = *((_BYTE *)src + 12);
      *(_DWORD *)dest = v27;
      *((_DWORD *)dest + 1) = v28;
      *((_DWORD *)dest + 2) = v29;
      *((_BYTE *)dest + 12) = v30;
      break;
    case 0xEu:
      v31 = *(_DWORD *)src;
      v32 = *((_DWORD *)src + 1);
      v33 = *((_DWORD *)src + 2);
      v34 = *((_WORD *)src + 6);
      *(_DWORD *)dest = v31;
      *((_DWORD *)dest + 1) = v32;
      *((_DWORD *)dest + 2) = v33;
      *((_WORD *)dest + 6) = v34;
      break;
    case 0xFu:
      v35 = *((_BYTE *)src + 14);
      *((_WORD *)dest + 6) = *((_WORD *)src + 6);
      *((_BYTE *)dest + 14) = v35;
      v36 = *(_DWORD *)src;
      v37 = *((_DWORD *)src + 1);
      v38 = *((_DWORD *)src + 2);
      *(_DWORD *)dest = v36;
      *((_DWORD *)dest + 1) = v37;
      *((_DWORD *)dest + 2) = v38;
      break;
    default:
      if ( (((unsigned int)dest ^ (unsigned int)src) & 3) != 0 )
        dest = _memcpy_reverse_large_neon();
      else
        dest = off_40510C();
      break;
  }
  return dest;
}


// Function: _memcpy_reverse_large_integer
int __fastcall memcpy_reverse_large_integer(int result, int a2, unsigned int a3)
{
  unsigned int v3; // r3
  unsigned int v4; // r1
  bool v5; // cf
  char v6; // t1
  __int16 v7; // t1
  unsigned int v8; // r2
  int v9; // r4
  int v10; // r5
  int v11; // r6
  int v12; // r7
  int v13; // r8
  int v14; // r9
  int v15; // r12
  int v16; // lr
  int v17; // r4
  int v18; // r5
  int v19; // r6
  int v20; // r7
  int v21; // r8
  int v22; // r9
  int v23; // r12
  int v24; // lr
  unsigned int i; // r2
  __int64 v26; // t1
  unsigned int v27; // r2
  int v28; // t1
  int v29; // r5
  int v30; // r6
  int v31; // r7
  int v32; // r8
  int v33; // r9
  int v34; // r12
  int v35; // lr
  unsigned int j; // r2
  __int64 v37; // r4
  int v38; // t1

  v3 = result + a3;
  v4 = a2 + a3;
  v5 = __CFSHL__(result + a3, 31);
  __pld((void *)(v4 - 32));
  if ( ((result + a3) & 1) != 0 )
  {
    v6 = *(_BYTE *)--v4;
    --a3;
    *(_BYTE *)--v3 = v6;
    v5 = __CFSHL__(v3, 31);
  }
  if ( v5 )
  {
    v7 = *(_WORD *)(v4 - 2);
    v4 -= 2;
    a3 -= 2;
    *(_WORD *)(v3 - 2) = v7;
    v3 -= 2;
  }
  if ( (v4 & 3) == 0 )
  {
    v5 = a3 >= 0x20;
    v8 = a3 - 32;
    if ( v5 )
    {
      v5 = v8 >= 0x20;
      v8 -= 32;
      __pld((void *)(v4 - 64));
      for ( ; v5; v3 -= 32 )
      {
        __pld((void *)(v4 - 96));
        v5 = v8 >= 0x20;
        v8 -= 32;
        v9 = *(_DWORD *)(v4 - 32);
        v10 = *(_DWORD *)(v4 - 28);
        v11 = *(_DWORD *)(v4 - 24);
        v12 = *(_DWORD *)(v4 - 20);
        v13 = *(_DWORD *)(v4 - 16);
        v14 = *(_DWORD *)(v4 - 12);
        v15 = *(_DWORD *)(v4 - 8);
        v16 = *(_DWORD *)(v4 - 4);
        v4 -= 32;
        *(_DWORD *)(v3 - 32) = v9;
        *(_DWORD *)(v3 - 28) = v10;
        *(_DWORD *)(v3 - 24) = v11;
        *(_DWORD *)(v3 - 20) = v12;
        *(_DWORD *)(v3 - 16) = v13;
        *(_DWORD *)(v3 - 12) = v14;
        *(_DWORD *)(v3 - 8) = v15;
        *(_DWORD *)(v3 - 4) = v16;
      }
      v17 = *(_DWORD *)(v4 - 32);
      v18 = *(_DWORD *)(v4 - 28);
      v19 = *(_DWORD *)(v4 - 24);
      v20 = *(_DWORD *)(v4 - 20);
      v21 = *(_DWORD *)(v4 - 16);
      v22 = *(_DWORD *)(v4 - 12);
      v23 = *(_DWORD *)(v4 - 8);
      v24 = *(_DWORD *)(v4 - 4);
      v4 -= 32;
      *(_DWORD *)(v3 - 32) = v17;
      *(_DWORD *)(v3 - 28) = v18;
      *(_DWORD *)(v3 - 24) = v19;
      *(_DWORD *)(v3 - 20) = v20;
      *(_DWORD *)(v3 - 16) = v21;
      *(_DWORD *)(v3 - 12) = v22;
      *(_DWORD *)(v3 - 8) = v23;
      *(_DWORD *)(v3 - 4) = v24;
      v3 -= 32;
    }
    v5 = __CFADD__(v8, 24);
    for ( i = v8 + 24; v5; v3 -= 8 )
    {
      v5 = i >= 8;
      i -= 8;
      v26 = *(_QWORD *)(v4 - 8);
      v4 -= 8;
      *(_QWORD *)(v3 - 8) = v26;
    }
    if ( v4 == i + 8 )
      return result;
LABEL_26:
    JUMPOUT(0x402DB0);
  }
  v5 = a3 >= 0x40;
  v27 = a3 - 64;
  if ( v5 )
  {
    __pld((void *)(v4 - 64));
    do
    {
      __pld((void *)(v4 - 96));
      v5 = v27 >= 0x20;
      v27 -= 32;
      v28 = *(_DWORD *)(v4 - 32);
      v4 -= 32;
      v29 = *(_DWORD *)(v4 + 4);
      v30 = *(_DWORD *)(v4 + 8);
      v31 = *(_DWORD *)(v4 + 12);
      v32 = *(_DWORD *)(v4 + 16);
      v33 = *(_DWORD *)(v4 + 20);
      v34 = *(_DWORD *)(v4 + 24);
      v35 = *(_DWORD *)(v4 + 28);
      *(_DWORD *)(v3 - 32) = v28;
      *(_DWORD *)(v3 - 28) = v29;
      *(_DWORD *)(v3 - 24) = v30;
      *(_DWORD *)(v3 - 20) = v31;
      *(_DWORD *)(v3 - 16) = v32;
      *(_DWORD *)(v3 - 12) = v33;
      *(_DWORD *)(v3 - 8) = v34;
      *(_DWORD *)(v3 - 4) = v35;
      v3 -= 32;
    }
    while ( v5 );
  }
  v5 = __CFADD__(v27, 56);
  for ( j = v27 + 56; v5; v3 -= 8 )
  {
    v5 = j >= 8;
    j -= 8;
    v38 = *(_DWORD *)(v4 - 8);
    v4 -= 8;
    LODWORD(v37) = v38;
    HIDWORD(v37) = *(_DWORD *)(v4 + 4);
    *(_QWORD *)(v3 - 8) = v37;
  }
  if ( v4 != j + 8 )
    goto LABEL_26;
  return result;
}


// Function: __memcpy_reverse_large_neon
int __fastcall _memcpy_reverse_large_neon(int result, int a2, unsigned int a3)
{
  int v3; // r3
  int v4; // r1
  bool v5; // cf
  char v6; // t1
  __int16 v7; // t1
  unsigned int v8; // r2
  __int64 v9; // d1
  __int64 v10; // d2
  __int64 v11; // d3
  __int64 v12; // d1
  __int64 v13; // d2
  __int64 v14; // d3
  unsigned int i; // r2
  int v16; // t1
  int v17; // r5

  v3 = result + a3;
  v4 = a2 + a3;
  v5 = __CFSHL__(result + a3, 31);
  __pld((void *)(v4 - 32));
  if ( ((result + a3) & 1) != 0 )
  {
    v6 = *(_BYTE *)--v4;
    --a3;
    *(_BYTE *)--v3 = v6;
    v5 = __CFSHL__(v3, 31);
  }
  if ( v5 )
  {
    v7 = *(_WORD *)(v4 - 2);
    v4 -= 2;
    a3 -= 2;
    *(_WORD *)(v3 - 2) = v7;
    v3 -= 2;
  }
  v5 = a3 >= 0x20;
  v8 = a3 - 32;
  if ( v5 )
  {
    v5 = v8 >= 0x20;
    v8 -= 32;
    __pld((void *)(v4 - 64));
    for ( ; v5; *(_QWORD *)(v3 + 24) = v11 )
    {
      __pld((void *)(v4 - 96));
      v4 -= 32;
      v3 -= 32;
      v5 = v8 >= 0x20;
      v8 -= 32;
      v9 = *(_QWORD *)(v4 + 8);
      v10 = *(_QWORD *)(v4 + 16);
      v11 = *(_QWORD *)(v4 + 24);
      *(_QWORD *)v3 = *(_QWORD *)v4;
      *(_QWORD *)(v3 + 8) = v9;
      *(_QWORD *)(v3 + 16) = v10;
    }
    v4 -= 32;
    v3 -= 32;
    v12 = *(_QWORD *)(v4 + 8);
    v13 = *(_QWORD *)(v4 + 16);
    v14 = *(_QWORD *)(v4 + 24);
    *(_QWORD *)v3 = *(_QWORD *)v4;
    *(_QWORD *)(v3 + 8) = v12;
    *(_QWORD *)(v3 + 16) = v13;
    *(_QWORD *)(v3 + 24) = v14;
  }
  v5 = __CFADD__(v8, 24);
  for ( i = v8 + 24; v5; *(_DWORD *)(v3 + 4) = v17 )
  {
    v16 = *(_DWORD *)(v4 - 8);
    v4 -= 8;
    v17 = *(_DWORD *)(v4 + 4);
    v5 = i >= 8;
    i -= 8;
    *(_DWORD *)(v3 - 8) = v16;
    v3 -= 8;
  }
  if ( v4 != i + 8 )
    JUMPOUT(0x402DB0);
  return result;
}


// Function: _memcpy_decide
int __fastcall memcpy_decide()
{
  int (**v0)(void); // r12
  unsigned int v1; // r4
  int v2; // r5
  unsigned int v3; // r4

  if ( (__get_CPSR() & 0xF) != 0 )
  {
    v1 = __mrc(15, 0, 0, 0, 0);
    v2 = HIBYTE(v1);
    v3 = v1 >> 4;
    if ( v2 == 65 && (v3 & 0xFFF) == 0xC09 )
      goto LABEL_6;
LABEL_7:
    off_405108 = (int (*)(void))_memcpy_forward_large_neon;
    off_40510C = (void *(*)(void))_memcpy_reverse_large_neon;
    return (*v0)();
  }
  if ( !MEMORY[0x7FFE028E] )
    goto LABEL_7;
LABEL_6:
  off_405108 = (int (*)(void))_memcpy_forward_large_integer;
  off_40510C = (void *(*)(void))memcpy_reverse_large_integer;
  return (*v0)();
}


// Function: FxStubDriverUnloadCommon
void __fastcall FxStubDriverUnloadCommon()
{
  FxStubUnbindClasses(&WdfBindInfo);
  WdfVersionUnbind_0();
}


// Function: FxStubDriverUnload
void __fastcall FxStubDriverUnload(_DRIVER_OBJECT *DriverObject)
{
  if ( WdfDriverStubDisplacedDriverUnload && (char *)WdfDriverStubDisplacedDriverUnload != (char *)FxStubDriverUnload )
    WdfDriverStubDisplacedDriverUnload(DriverObject);
  FxStubDriverUnloadCommon();
}


// Function: j_FxStubDriverUnloadCommon
// attributes: thunk
void __fastcall j_FxStubDriverUnloadCommon()
{
  FxStubDriverUnloadCommon();
}


// Function: FxDriverEntryWorker
int __fastcall FxDriverEntryWorker(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)
{
  int inited; // r4

  if ( !DriverObject )
    return DriverEntry(0, RegistryPath);
  WdfDriverStubRegistryPath.Length = 0;
  WdfDriverStubRegistryPath.MaximumLength = 520;
  WdfDriverStubDriverObject = DriverObject;
  WdfDriverStubRegistryPath.Buffer = WdfDriverStubRegistryPathBuffer;
  RtlCopyUnicodeString(&WdfDriverStubRegistryPath, RegistryPath);
  inited = WdfVersionBind_0();
  if ( inited >= 0 )
  {
    inited = FxStubBindClasses(&WdfBindInfo);
    if ( inited < 0
      || (inited = FxStubInitTypes(), inited < 0)
      || (inited = DriverEntry(DriverObject, RegistryPath), inited < 0) )
    {
      FxStubDriverUnloadCommon();
    }
    else
    {
      if ( *(_BYTE *)(WdfDriverGlobals + 44) )
      {
        if ( DriverObject->DriverUnload )
          WdfDriverStubDisplacedDriverUnload = (int (__fastcall *)(_DWORD))DriverObject->DriverUnload;
        DriverObject->DriverUnload = FxStubDriverUnload;
      }
      else if ( (*(_DWORD *)(WdfDriverGlobals + 4) & 2) != 0 )
      {
        WdfDriverStubOriginalWdfDriverMiniportUnload = (int)WdfFunctions.WdfDriverMiniportUnload;
        WdfFunctions.WdfDriverMiniportUnload = (WDF_DRIVER_MINIPORT_UNLOAD *)j_FxStubDriverUnloadCommon;
      }
      return 0;
    }
  }
  return inited;
}


// Function: FxDriverEntry
int __fastcall FxDriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)
{
  _security_init_cookie();
  return FxDriverEntryWorker(DriverObject, RegistryPath);
}


// Function: FxStubUnbindClasses
void __fastcall FxStubUnbindClasses(_WDF_BIND_INFO *WdfBindInfo)
{
  _DWORD *v2; // r4
  void (__fastcall *v3)(int (*)(), _WDF_BIND_INFO *, int, _DWORD *); // r5

  v2 = &unk_4051B8;
  if ( off_4051BC != &unk_4051B0 && &unk_4051B8 <= off_4051BC )
  {
    do
    {
      v3 = (void (__fastcall *)(int (*)(), _WDF_BIND_INFO *, int, _DWORD *))v2[9];
      if ( v3 )
        v3(WdfVersionUnbindClass_0, WdfBindInfo, WdfDriverGlobals, v2);
      else
        WdfVersionUnbindClass_0();
      v2 += 11;
    }
    while ( v2 <= (_DWORD *)off_4051BC );
  }
}


// Function: FxStubBindClasses
int __fastcall FxStubBindClasses(_WDF_BIND_INFO *WdfBindInfo)
{
  int result; // r0

  result = 0;
  if ( &unk_4051B0 > &unk_4051B8 )
    return -1073741701;
  return result;
}


// Function: FxStubInitTypes
int __fastcall FxStubInitTypes()
{
  if ( &unk_4051C0 <= &unk_4051C8 )
    return 0;
  else
    return -1073741701;
}


// Function: WdfVersionBind_0
// attributes: thunk
int WdfVersionBind_0()
{
  return WdfVersionBind();
}


// Function: WdfVersionUnbind_0
// attributes: thunk
int WdfVersionUnbind_0()
{
  return WdfVersionUnbind();
}


// Function: WdfVersionUnbindClass_0
// attributes: thunk
int WdfVersionUnbindClass_0()
{
  return WdfVersionUnbindClass();
}


// Function: WdfVersionBindClass_0
// attributes: thunk
int WdfVersionBindClass_0()
{
  return WdfVersionBindClass();
}


// Function: __rt_udiv
int __fastcall _rt_udiv(unsigned int a1, unsigned int a2)
{
  signed int v2; // r0
  signed int v3; // r3
  bool v4; // cc
  int (__fastcall *v5)(_DWORD); // r3
  int result; // r0

  if ( !a1 )
    __brkdiv0();
  v2 = __clz(a1);
  v3 = __clz(a2);
  v4 = v2 < v3;
  v5 = (int (__fastcall *)(_DWORD))((char *)&loc_403648 - 2 * (v2 - v3) + -8 * (v2 - v3));
  result = 0;
  if ( !v4 )
    return v5(0);
  return result;
}


// Function: __rt_udiv64
int __fastcall _rt_udiv64(__int64 a1, unsigned __int64 a2)
{
  __int64 v2; // kr00_8
  signed int v3; // r1
  signed int v4; // r0
  bool v5; // cc
  unsigned int v6; // r0
  unsigned __int64 v7; // r4
  char v8; // r0
  unsigned int v9; // r1
  int v11; // off

  if ( !a1 )
    __brkdiv0();
  if ( HIDWORD(a1) | HIDWORD(a2) )
  {
    v2 = a1;
    v3 = __clz(HIDWORD(a2));
    if ( !HIDWORD(a2) )
      v3 = __clz(a2) + 32;
    v4 = __clz(HIDWORD(v2));
    if ( !HIDWORD(v2) )
      v4 = __clz(v2) + 32;
    v5 = v4 < v3;
    v6 = v4 - v3;
    if ( v5 )
    {
      LODWORD(a1) = 0;
    }
    else
    {
      v7 = v2;
      if ( v6 >= 0x20 )
      {
        HIDWORD(v7) = v2;
        LODWORD(v7) = 0;
      }
      v8 = v6 & 0x1F;
      v9 = (unsigned int)v7 >> (32 - v8);
      LODWORD(v7) = (_DWORD)v7 << v8;
      HIDWORD(v7) = (HIDWORD(v7) << v8) | v9;
      a1 = 0;
      while ( 1 )
      {
        if ( v7 <= a2 )
        {
          a2 -= v7;
          ++a1;
        }
        if ( v7 == v2 )
          break;
        v11 = (a1 + (unsigned __int64)(unsigned int)a1) >> 32;
        LODWORD(a1) = 2 * a1;
        HIDWORD(a1) += v11;
        v7 >>= 1;
      }
    }
  }
  else
  {
    LODWORD(a1) = (unsigned int)a2 / (unsigned int)a1;
  }
  return a1;
}


// Function: __rt_sdiv64
int __fastcall _rt_sdiv64(__int64 a1, __int64 a2)
{
  unsigned int v2; // r4
  bool v3; // cf
  int v4; // r7
  __int64 v5; // kr00_8
  signed int v6; // r1
  signed int v7; // r0
  bool v8; // cc
  unsigned int v9; // r0
  unsigned __int64 v10; // r4
  char v11; // r0
  unsigned int v12; // r1
  int v14; // off

  v2 = HIDWORD(a1) & 0x80000000;
  if ( a1 < 0 )
  {
    v3 = (_DWORD)a1 == 0;
    LODWORD(a1) = -(int)a1;
    HIDWORD(a1) -= 2 * HIDWORD(a1) + !v3;
  }
  v4 = v2 ^ (SHIDWORD(a2) >> 31);
  if ( a2 < 0 )
  {
    v3 = (_DWORD)a2 == 0;
    LODWORD(a2) = -(int)a2;
    HIDWORD(a2) -= 2 * HIDWORD(a2) + !v3;
  }
  if ( !a1 )
    __brkdiv0();
  if ( HIDWORD(a1) | HIDWORD(a2) )
  {
    v5 = a1;
    v6 = __clz(HIDWORD(a2));
    if ( !HIDWORD(a2) )
      v6 = __clz(a2) + 32;
    v7 = __clz(HIDWORD(v5));
    if ( !HIDWORD(v5) )
      v7 = __clz(v5) + 32;
    v8 = v7 < v6;
    v9 = v7 - v6;
    if ( v8 )
    {
      LODWORD(a1) = 0;
    }
    else
    {
      v10 = v5;
      if ( v9 >= 0x20 )
      {
        HIDWORD(v10) = v5;
        LODWORD(v10) = 0;
      }
      v11 = v9 & 0x1F;
      v12 = (unsigned int)v10 >> (32 - v11);
      LODWORD(v10) = (_DWORD)v10 << v11;
      HIDWORD(v10) = (HIDWORD(v10) << v11) | v12;
      a1 = 0;
      while ( 1 )
      {
        if ( v10 <= a2 )
        {
          a2 -= v10;
          ++a1;
        }
        if ( v10 == v5 )
          break;
        v14 = (a1 + (unsigned __int64)(unsigned int)a1) >> 32;
        LODWORD(a1) = 2 * a1;
        HIDWORD(a1) += v14;
        v10 >>= 1;
      }
    }
  }
  else
  {
    LODWORD(a1) = (unsigned int)a2 / (unsigned int)a1;
  }
  if ( __CFSHL__(v4, 1) )
    LODWORD(a1) = -(int)a1;
  return a1;
}


// Function: __security_push_cookie
void _security_push_cookie()
{
  ;
}


// Function: __security_pop_cookie
// positive sp value has been detected, the output may be wrong!
void _security_pop_cookie()
{
  ;
}


// Function: _ppgsfailure
void __fastcall ppgsfailure()
{
  ;
}


// Function: memset
void *__fastcall memset(void *dest, int c, size_t count)
{
  bool v3; // zf
  bool v4; // cc
  signed int v5; // r2
  char *v6; // r3
  int v7; // r1
  int i; // r2
  int *v9; // r3
  int v10; // r2

  v3 = count == 4;
  v4 = (int)count < 4;
  v5 = count - 4;
  v6 = (char *)dest;
  if ( !v4 )
  {
    v7 = (unsigned __int8)c | ((unsigned __int8)c << 8);
    if ( ((unsigned __int8)dest & 3) != 0 )
    {
      if ( ((unsigned __int8)dest & 1) != 0 )
      {
        --v5;
        *(_BYTE *)dest = v7;
        v6 = (char *)dest + 1;
      }
      if ( ((unsigned __int8)v6 & 2) != 0 )
      {
        v5 -= 2;
        *(_WORD *)v6 = v7;
        v6 += 2;
      }
    }
    c = v7 | (v7 << 16);
    v4 = v5 < 12;
    for ( i = v5 - 12; !v4; v6 = (char *)(v9 + 2) )
    {
      *(_DWORD *)v6 = c;
      *((_DWORD *)v6 + 1) = c;
      v9 = (int *)(v6 + 8);
      v4 = i < 16;
      i -= 16;
      *v9 = c;
      v9[1] = c;
    }
    v4 = i < -8;
    v10 = i + 8;
    if ( !v4 )
    {
      *(_DWORD *)v6 = c;
      *((_DWORD *)v6 + 1) = c;
      v6 += 8;
      v10 -= 8;
    }
    v3 = v10 == -4;
    v4 = v10 < -4;
    v5 = v10 + 4;
    if ( !v4 )
    {
      *(_DWORD *)v6 = c;
      v6 += 4;
    }
  }
  if ( v4 )
  {
    v5 += 4;
    v3 = v5 == 0;
  }
  if ( !v3 )
  {
    *v6 = c;
    if ( v5 >= 2 )
    {
      v6[1] = c;
      if ( v5 > 2 )
        v6[2] = c;
    }
  }
  return dest;
}


// Function: _GSHandlerCheck
int __fastcall GSHandlerCheck(
        _EXCEPTION_RECORD *ExceptionRecord,
        void *EstablisherFrame,
        _CONTEXT *ContextRecord,
        _DISPATCHER_CONTEXT *DispatcherContext)
{
  return 1;
}


// Function: WppLoadTracingSupport
int __fastcall WppLoadTracingSupport()
{
  unsigned int v1; // [sp+0h] [bp-18h] BYREF
  struct _UNICODE_STRING v2; // [sp+8h] [bp-10h] BYREF

  v1 = 0;
  RtlInitUnicodeString(&v2, L"PsGetVersion");
  pfnWppGetVersion = (unsigned __int8 (__fastcall *)(unsigned int *, unsigned int *, unsigned int *, _UNICODE_STRING *))MmGetSystemRoutineAddress(&v2);
  RtlInitUnicodeString(&v2, L"WmiTraceMessage");
  pfnWppTraceMessage = (int (*)(unsigned __int64, unsigned int, const _GUID *, unsigned __int16, ...))MmGetSystemRoutineAddress(&v2);
  RtlInitUnicodeString(&v2, L"WmiQueryTraceInformation");
  pfnWppQueryTraceInformation = (int (__fastcall *)(_TRACE_INFORMATION_CLASS, void *, unsigned int, unsigned int *, void *))MmGetSystemRoutineAddress(&v2);
  WPPTraceSuite = WppTraceWinXP;
  if ( pfnWppGetVersion )
    pfnWppGetVersion(&v1, 0, 0, 0);
  if ( v1 >= 6 )
  {
    RtlInitUnicodeString(&v2, L"EtwRegisterClassicProvider");
    pfnEtwRegisterClassicProvider = (void (__fastcall *)(const _GUID *, unsigned int, void (__fastcall *)(const _GUID *, unsigned __int8, void *, void *), void *, unsigned __int64 *))MmGetSystemRoutineAddress(&v2);
    if ( pfnEtwRegisterClassicProvider )
    {
      RtlInitUnicodeString(&v2, L"EtwUnregister");
      pfnEtwUnregister = (int (__fastcall *)(unsigned __int64))MmGetSystemRoutineAddress(&v2);
      WPPTraceSuite = WppTraceServer08;
    }
  }
  return v1;
}


// Function: WppTraceCallback
int __fastcall WppTraceCallback(
        int MinorFunction,
        void *DataPath,
        unsigned int BufferLength,
        void *Buffer,
        void *Context,
        unsigned int *Size)
{
  _DWORD *v7; // r6
  _DWORD *v8; // r7
  unsigned int v9; // r4
  unsigned __int16 *v10; // r8
  _DWORD *v11; // r1
  int result; // r0
  int v13; // r9
  unsigned int v14; // r5
  _DWORD *v15; // r0
  int v16; // r3
  char *v17; // r5
  int v18; // r2
  char v19; // r3
  int v20; // [sp+8h] [bp-30h] BYREF
  unsigned int v21; // [sp+Ch] [bp-2Ch] BYREF
  int v22; // [sp+10h] [bp-28h]

  *Size = 0;
  v7 = Buffer;
  switch ( MinorFunction )
  {
    case 4:
    case 5:
      v17 = (char *)Context;
      if ( Context )
      {
        if ( BufferLength < 0x30 )
          goto LABEL_5;
        while ( RtlCompareMemory(*((VOID **)v17 + 1), v7 + 6, 0x10u) != 16 )
        {
          v17 = (char *)*((_DWORD *)v17 + 2);
          if ( !v17 )
            goto LABEL_21;
        }
        result = 0;
        if ( MinorFunction == 5 )
        {
          v17[29] = 0;
          *((_DWORD *)v17 + 8) = 0;
          *((_DWORD *)v17 + 4) = 0;
          *((_DWORD *)v17 + 5) = 0;
        }
        else
        {
          v18 = v7[3];
          v22 = v7[2];
          *((_DWORD *)v17 + 4) = v22;
          *((_DWORD *)v17 + 5) = v18;
          if ( WPPTraceSuite == WppTraceWinXP )
          {
            if ( !pfnWppQueryTraceInformation(TraceEnableLevelClass, &v20, 4u, &v21, v7) )
              v17[29] = v20;
            result = pfnWppQueryTraceInformation(TraceEnableFlagsClass, v17 + 32, 4u, &v21, v7);
          }
          else
          {
            v19 = BYTE2(v22);
            *((_DWORD *)v17 + 8) = v18;
            v17[29] = v19;
          }
        }
      }
      else
      {
LABEL_21:
        result = -1073741163;
      }
      break;
    case 6:
    case 7:
      result = 0;
      break;
    case 8:
      v8 = Context;
      v9 = 0;
      v10 = (unsigned __int16 *)*((_DWORD *)Context + 6);
      v11 = Context;
      do
      {
        v11 = (_DWORD *)v11[2];
        ++v9;
      }
      while ( v11 );
      if ( v9 <= 0x3F )
      {
        if ( v10 )
        {
          v13 = 28 * v9 + 20;
          v14 = *v10 + v13 + 2;
        }
        else
        {
          v13 = 0;
          v14 = 28 * v9 + 20;
        }
        if ( v14 > BufferLength )
        {
          result = -1073741789;
          if ( BufferLength >= 4 )
          {
            *(_DWORD *)Buffer = v14;
            *Size = 4;
          }
        }
        else
        {
          memset(Buffer, 0, BufferLength);
          *v7 = v14;
          v7[2] = v13;
          v7[4] = v9;
          if ( v10 )
          {
            *(_WORD *)((char *)v7 + v13) = *v10;
            _memcpy_forward_new((int)v7 + v13 + 2, *((_DWORD *)v10 + 1), *v10);
          }
          for ( ; v9; v8 = (_DWORD *)v8[2] )
          {
            v15 = (_DWORD *)v8[1];
            --v9;
            v7[5] = *v15;
            v7[6] = v15[1];
            v7[7] = v15[2];
            v7 += 7;
            v16 = v15[3];
            v7[2] = 528384;
            v7[1] = v16;
            *((_BYTE *)v8 + 29) = 0;
            v8[8] = 0;
          }
          *Size = v14;
          result = 0;
        }
      }
      else
      {
LABEL_5:
        result = -1073741811;
      }
      break;
    default:
      result = -1073741808;
      break;
  }
  return result;
}


// Function: WppInitKm
void __fastcall WppInitKm(_DEVICE_OBJECT *DevObject, const _UNICODE_STRING *RegPath)
{
  int *v2; // r5
  int v3; // r0
  void (__fastcall *v4)(const _GUID *, unsigned int, void (__fastcall *)(const _GUID *, unsigned __int8, void *, void *), void *, unsigned __int64 *); // r4

  v2 = &dword_405B20;
  if ( off_405130 != (_UNKNOWN *)&dword_405B20 )
  {
    off_405130 = &dword_405B20;
    if ( WPPTraceSuite == WppTraceServer08 )
    {
      do
      {
        v3 = v2[1];
        v4 = pfnEtwRegisterClassicProvider;
        v2[10] = 0;
        v2[11] = 0;
        ((void (__fastcall *)(int, _DWORD, int (*)(), int *))v4)(v3, 0, sub_4011C8, v2);
        v2 = (int *)v2[2];
      }
      while ( v2 );
    }
    else if ( WPPTraceSuite == WppTraceWinXP )
    {
      dword_405B20 = (int)WppTraceCallback;
      IoWMIRegistrationControl((_DEVICE_OBJECT *)&dword_405B20, 0x80010001);
    }
  }
}


// Function: WppCleanupKm
void __fastcall WppCleanupKm(_DEVICE_OBJECT *DeviceObject)
{
  _QWORD *v1; // r4
  unsigned __int64 v2; // r0

  v1 = off_405130;
  if ( off_405130 == (_UNKNOWN *)&off_405130 )
    return;
  if ( WPPTraceSuite != WppTraceServer08 )
  {
    if ( WPPTraceSuite == WppTraceWinXP )
      IoWMIRegistrationControl((_DEVICE_OBJECT *)off_405130, 0x80000002);
    goto LABEL_10;
  }
  if ( !off_405130 )
  {
LABEL_10:
    off_405130 = &off_405130;
    return;
  }
  do
  {
    v2 = v1[5];
    if ( v2 )
      pfnEtwUnregister(v2);
    v1 = (_QWORD *)*((_DWORD *)v1 + 2);
  }
  while ( v1 );
  off_405130 = &off_405130;
}


// Function: __security_init_cookie
void _security_init_cookie()
{
  int *v0; // r1
  int v1; // r2
  unsigned int v2; // r3

  v0 = off_408038;
  v1 = dword_408034;
  v2 = *off_408038;
  if ( !*off_408038 || v2 == dword_408034 )
  {
    v2 = **(_DWORD **)off_408030 ^ (unsigned int)off_408038;
    *off_408038 = v2;
    if ( !v2 )
    {
      v2 = v1;
      *v0 = v1;
    }
  }
  *off_40802C = ~v2;
}


