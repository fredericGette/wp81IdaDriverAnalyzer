// Function: ETW_EnableCallback
void __fastcall ETW_EnableCallback(
        const _GUID *SourceId,
        unsigned int ControlCode,
        unsigned __int8 Level,
        unsigned __int64 MatchAnyKeyword,
        unsigned __int64 MatchAllKeyword,
        _EVENT_FILTER_DESCRIPTOR *FilterData,
        void *CallbackContext)
{
  if ( CallbackContext )
  {
    if ( ControlCode )
    {
      if ( ControlCode == 1 )
      {
        *((_BYTE *)CallbackContext + 40) = Level;
        *((_QWORD *)CallbackContext + 2) = MatchAnyKeyword;
        *((_QWORD *)CallbackContext + 3) = MatchAllKeyword;
        *((_DWORD *)CallbackContext + 9) = 1;
      }
    }
    else
    {
      *((_BYTE *)CallbackContext + 40) = 0;
      *((_DWORD *)CallbackContext + 4) = 0;
      *((_DWORD *)CallbackContext + 5) = 0;
      *((_DWORD *)CallbackContext + 6) = 0;
      *((_DWORD *)CallbackContext + 7) = 0;
      *((_DWORD *)CallbackContext + 9) = 0;
    }
  }
}


// Function: McGenEventRegister
int __fastcall McGenEventRegister(
        const _GUID *ProviderId,
        void (__fastcall *EnableCallback)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *),
        void *CallbackContext,
        unsigned __int64 *RegHandle)
{
  if ( *RegHandle )
    return 0;
  else
    return EtwRegister(ProviderId, ETW_EnableCallback, CallbackContext, RegHandle);
}


// Function: McGenEventUnregister
int __fastcall McGenEventUnregister(unsigned __int64 *RegHandle)
{
  int result; // r0

  if ( !ETW_RegistrationHandle_02 )
    return 0;
  result = EtwUnregister((unsigned __int64 *)ETW_RegistrationHandle_02);
  ETW_RegistrationHandle_02 = 0;
  return result;
}


// Function: EventWrite_01
int __fastcall EventWrite_01(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5)
{
  char *v5; // r4
  unsigned int v7; // r6
  unsigned int v8; // r7
  size_t v9; // r3
  char *v10; // r4
  size_t v11; // r3
  unsigned int v13[9]; // [sp+8h] [bp-38h] BYREF

  v5 = a4;
  v7 = HIDWORD(RegHandle);
  v8 = RegHandle;
  if ( a4 )
  {
    v9 = strlen(a4) + 1;
  }
  else
  {
    v5 = "NULL";
    v9 = 5;
  }
  v13[0] = (unsigned int)v5;
  v10 = a5;
  v13[2] = v9;
  v13[1] = 0;
  v13[3] = 0;
  if ( a5 )
  {
    v11 = strlen(a5) + 1;
  }
  else
  {
    v10 = "NULL";
    v11 = 5;
  }
  v13[6] = v11;
  v13[7] = 0;
  v13[4] = (unsigned int)v10;
  v13[5] = 0;
  return EtwWrite(__PAIR64__(v7, v8), EventDescriptor, 0, 2u, v13);
}


// Function: EventWrite_02
int EventWrite_02(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5,
        ...)
{
  char *v5; // r4
  unsigned int v7; // r6
  unsigned int v8; // r7
  size_t v9; // r3
  char *v10; // r4
  size_t v11; // r3
  unsigned int var34[19]; // [sp+8h] [bp-48h] BYREF
  va_list va; // [sp+70h] [bp+20h] BYREF

  va_start(va, a5);
  v5 = a4;
  v7 = HIDWORD(RegHandle);
  v8 = RegHandle;
  if ( a4 )
  {
    v9 = strlen(a4) + 1;
  }
  else
  {
    v5 = "NULL";
    v9 = 5;
  }
  var34[0] = (unsigned int)v5;
  v10 = a5;
  var34[2] = v9;
  var34[1] = 0;
  var34[3] = 0;
  if ( a5 )
  {
    v11 = strlen(a5) + 1;
  }
  else
  {
    v10 = "NULL";
    v11 = 5;
  }
  var34[6] = v11;
  var34[7] = 0;
  va_copy((va_list)&var34[8], va);
  var34[9] = 0;
  var34[10] = 4;
  var34[11] = 0;
  var34[4] = (unsigned int)v10;
  var34[5] = 0;
  return EtwWrite(__PAIR64__(v7, v8), EventDescriptor, 0, 3u, var34);
}


// Function: EventWrite_03
int EventWrite_03(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5,
        ...)
{
  char *v5; // r4
  unsigned int v7; // r6
  unsigned int v8; // r7
  size_t v9; // r3
  char *v10; // r4
  size_t v11; // r3
  unsigned int var44[23]; // [sp+8h] [bp-58h] BYREF
  int v14; // [sp+80h] [bp+20h] BYREF
  va_list va1; // [sp+84h] [bp+24h] BYREF
  va_list va; // [sp+80h] [bp+20h]

  va_start(va1, a5);
  va_start(va, a5);
  v14 = va_arg(va1, _DWORD);
  v5 = a4;
  v7 = HIDWORD(RegHandle);
  v8 = RegHandle;
  if ( a4 )
  {
    v9 = strlen(a4) + 1;
  }
  else
  {
    v5 = "NULL";
    v9 = 5;
  }
  var44[0] = (unsigned int)v5;
  v10 = a5;
  var44[2] = v9;
  var44[1] = 0;
  var44[3] = 0;
  if ( a5 )
  {
    v11 = strlen(a5) + 1;
  }
  else
  {
    v10 = "NULL";
    v11 = 5;
  }
  var44[6] = v11;
  var44[7] = 0;
  va_copy((va_list)&var44[8], va);
  var44[9] = 0;
  var44[10] = 4;
  var44[11] = 0;
  va_copy((va_list)&var44[12], va1);
  var44[13] = 0;
  var44[14] = 4;
  var44[15] = 0;
  var44[4] = (unsigned int)v10;
  var44[5] = 0;
  return EtwWrite(__PAIR64__(v7, v8), EventDescriptor, 0, 4u, var44);
}


// Function: DoTraceMessage_01
int __fastcall DoTraceMessage_01(unsigned __int64 a1, unsigned __int16 a2)
{
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2);
}


// Function: DoTraceMessage_02
int DoTraceMessage_02(unsigned __int64 a1, unsigned __int16 a2, int a3, ...)
{
  va_list va; // [sp+30h] [bp+18h] BYREF

  va_start(va, a3);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2, va, 4, 0);
}


// Function: DoTraceMessage_03
int DoTraceMessage_03(unsigned __int64 a1, unsigned __int16 a2, int a3, ...)
{
  int v4; // [sp+38h] [bp+18h] BYREF
  va_list va; // [sp+38h] [bp+18h]
  va_list va1; // [sp+3Ch] [bp+1Ch] BYREF

  va_start(va1, a3);
  va_start(va, a3);
  v4 = va_arg(va1, _DWORD);
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, a2, va, 4, va1, 4, 0);
}


// Function: DoTraceMessage_04
int DoTraceMessage_04(unsigned __int64 a1, int a2, int a3, ...)
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
  return pfnWppTraceMessage(a1, 0x2Bu, &WPP_Traceguids_01, 0x85u, va, 4, va1, 4, va2, 4, 0);
}


// Function: DoTraceMessage_05
int DoTraceMessage_05(unsigned __int64 a1, unsigned __int16 a2, const _GUID *a3, ...)
{
  va_list va; // [sp+30h] [bp+18h] BYREF

  va_start(va, a3);
  return pfnWppTraceMessage(a1, 0x2Bu, a3, a2, va, 4, 0);
}


// Function: DoTraceMessage_06
int __fastcall DoTraceMessage_06(unsigned int a1, unsigned int a2)
{
  size_t v4; // r4
  size_t v5; // r0

  v4 = strlen(a194947);
  v5 = strlen(aMar242014);
  return pfnWppTraceMessage(__PAIR64__(a2, a1), 0x2Bu, &WPP_Traceguids_01, 0xAu, aMar242014, v5 + 1, a194947, v4 + 1, 0);
}


// Function: SmdSetContextFields
// This function is a configuration or initialization helper. It either copies a set of configuration values from one structure to another or clears a set of configuration values, depending on the input.
void __fastcall sub_401434(int a1, unsigned int a2, int a3, int a4)
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


// Function: SetupRPE
int __fastcall SetupRPE(void *a1)
{
  void (__fastcall *v2)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *); // r1
  int v3; // r0
  __int32 v4; // r4
  unsigned int v5; // r3
  unsigned __int64 v6; // r0
  int v8; // r5
  unsigned int v9; // r0
  int v10; // r0
  unsigned int v11; // r3
  unsigned __int64 v12; // r0
  int v13; // r0
  unsigned int v14; // r3
  unsigned __int64 v15; // r0
  NT_STATUS_VALUES v16; // r0
  unsigned int v17; // r3
  unsigned __int64 v18; // r0
  NT_STATUS_VALUES v19; // r0
  unsigned int v20; // r3
  unsigned __int64 v21; // r0
  unsigned __int64 v23; // r0
  NT_STATUS_VALUES inited; // r0
  unsigned int v26; // r3
  unsigned __int64 v27; // r0
  int v28; // r0
  unsigned int v29; // r3
  unsigned __int64 v30; // r0
  unsigned int v31; // r10
  NT_STATUS_VALUES v32; // r0
  unsigned int v33; // r3
  unsigned __int64 v34; // r0
  NT_STATUS_VALUES v35; // r0
  unsigned int v36; // r3
  unsigned __int64 v37; // r0
  unsigned __int64 v39; // r0
  _DWORD v40[4]; // [sp+28h] [bp-1B0h] BYREF
  unsigned int v41; // [sp+38h] [bp-1A0h]
  int v42; // [sp+3Ch] [bp-19Ch]
  int v43; // [sp+40h] [bp-198h]
  int v44; // [sp+44h] [bp-194h]
  int v45; // [sp+48h] [bp-190h] BYREF
  unsigned int v46; // [sp+4Ch] [bp-18Ch]
  int v47; // [sp+50h] [bp-188h]
  int v48; // [sp+54h] [bp-184h]
  int v49; // [sp+58h] [bp-180h]
  int v50; // [sp+5Ch] [bp-17Ch]
  int v51; // [sp+60h] [bp-178h] BYREF
  GUID v52; // [sp+64h] [bp-174h]
  int v53; // [sp+74h] [bp-164h]
  int v54; // [sp+78h] [bp-160h] BYREF
  GUID v55; // [sp+7Ch] [bp-15Ch]
  int v56; // [sp+8Ch] [bp-14Ch]
  GUID v57; // [sp+90h] [bp-148h] BYREF
  GUID v58; // [sp+A0h] [bp-138h] BYREF
  _DWORD v59[18]; // [sp+B0h] [bp-128h] BYREF
  char v60[12]; // [sp+F8h] [bp-E0h] BYREF
  int v61; // [sp+104h] [bp-D4h]
  int v62; // [sp+108h] [bp-D0h]
  int v63; // [sp+10Ch] [bp-CCh]
  int v64; // [sp+110h] [bp-C8h]
  int v65; // [sp+114h] [bp-C4h]
  int v66; // [sp+118h] [bp-C0h]
  int v67; // [sp+11Ch] [bp-BCh]
  int v68; // [sp+120h] [bp-B8h]
  int v69; // [sp+124h] [bp-B4h]
  int v70; // [sp+128h] [bp-B0h]
  int v71; // [sp+12Ch] [bp-ACh]
  int v72; // [sp+130h] [bp-A8h]
  int v73; // [sp+134h] [bp-A4h]
  _WORD v74[64]; // [sp+138h] [bp-A0h] BYREF

  v42 = (int)a1;
  strcpy(v60, "SMD (MODEM)");
  v61 = 0;
  v62 = 0;
  v63 = 0;
  v64 = 0;
  v65 = 0;
  v66 = 0;
  v67 = 0;
  v68 = 0;
  v69 = 0;
  v70 = 0;
  v71 = 0;
  v72 = 0;
  v73 = 0;
  strcpy((char *)v59, "SMD (RIVA)");
  memset((char *)&v59[2] + 3, 0, 53);
  v74[0] = 49;
  memset(&v74[1], 0, 0x7Eu);
  v58.Data1 = 0xF9D15453;                       // {F9D15453-8335-4C43-AA72-FCD925F135F3}
  *(_DWORD *)&v58.Data2 = 0x434C8335;
  *(_DWORD *)v58.Data4 = 0xD9FC72AA;
  *(_DWORD *)&v58.Data4[4] = 0xF335F125;
  v57.Data1 = 0xD30F94E9;                       // {D30F94E9-9C90-D54E-AE04-9266277C4721}
  *(_DWORD *)&v57.Data2 = 0x4ED59C90;
  *(_DWORD *)v57.Data4 = 0x669204AE;
  *(_DWORD *)&v57.Data4[4] = 0x21477C27;
  v41 = 0x93367D0F;
  v43 = 0;
  v44 = 0;
  v3 = RpeInit(a1, v2);
  v4 = v3;
  if ( v3 )
  {
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_02,
        &stru_40E398,
        (const _GUID *)&ETW_RegistrationHandle_02,
        "SetupRPE",
        "RpeInit failed",
        v3);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
    {
      v5 = *((unsigned __int8 *)off_40F178 + 29);
      if ( v5 >= 2 )
      {
        LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v6, 0x18u, v5, v4);
        return v4;
      }
    }
  }
  else
  {
    v40[0] = 16;
    v40[1] = SmdAlwaysTrueStatus;
    v40[2] = 0;
    v40[3] = 0;
    if ( off_415950 )
      v8 = off_415950();                        // sub_401D8C of qcsmem8930
    else
      v8 = 0;
    if ( off_415954 )
      v9 = ((int (*)(void))off_415954)();       // sub_401D3C of qcsmem8930
    else
      v9 = 0;
    v10 = RpeClientInit(&v58, (int)v60, (int)v74, v40, v8, v44, v9 >> 12, 0, (int)a1);
    v4 = v10;
    if ( !v10 || v10 == -536182528 )
    {
      v54 = 24;
      v55 = v58;
      v56 = 5;
      v13 = RpeSendState((int)&v54);
      v4 = v13;
      if ( !v13 || v13 == -536182528 )
      {
        v51 = 24;
        v53 = 4;
        v52.Data1 = 0x936DC601;                 // {936DC601-5530-824B-9D2A-72A488BEC7C1}
        *(_DWORD *)&v52.Data2 = 0x4B825530;
        *(_DWORD *)v52.Data4 = 0xA4722A9D;
        *(_DWORD *)&v52.Data4[4] = 0xC1C7BE88;
        v16 = RpeRegisterForStateNotification(&v58, &v51);
        v4 = v16;
        if ( v16 == STATUS_SUCCESS || v16 == -536182528 )
        {
          v51 = 24;
          v53 = 5;
          v52.Data1 = 0x936DC601;               // {936DC601-5530-824B-9D2A-72A488BEC7C1}
          *(_DWORD *)&v52.Data2 = 0x4B825530;
          *(_DWORD *)v52.Data4 = 0xA4722A9D;
          *(_DWORD *)&v52.Data4[4] = 0xC1C7BE88;
          v19 = RpeRegisterForStateNotification(&v58, &v51);
          v4 = v19;
          if ( v19 == STATUS_SUCCESS || v19 == -536182528 )
          {
            if ( dword_40FBB4 )
            {
              if ( (unsigned __int8)byte_40FBB8 >= 5u || !byte_40FBB8 )
                EventWrite_01(
                  ETW_RegistrationHandle_02,
                  &stru_40E2F8,
                  (const _GUID *)"SMD initialized with RPE for Apps-Modem edge",
                  "SetupRPE",
                  "SMD initialized with RPE for Apps-Modem edge");
            }
            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
            {
              LODWORD(v23) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v23) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_01(v23, 0x1Du);
            }
            if ( dword_415994 )
            {
              if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                EventWrite_05(
                  ETW_RegistrationHandle_01,
                  &stru_40E2F8,
                  (const _GUID *)&ETW_RegistrationHandle_01,
                  "RpeClientInit");
            }
            inited = RpeClientInitMultiSegment(&v57, (int)v59, (int)v74, v40, 0, 0, v42);
            v4 = inited;
            if ( inited == STATUS_SUCCESS || inited == -536182528 )
            {
              v54 = 24;
              v55 = v57;
              v56 = 5;
              v28 = RpeSendState((int)&v54);
              v4 = v28;
              if ( !v28 || v28 == -536182528 )
              {
                v45 = 24;
                v31 = v41;
                v47 = 0x4EC435CE;
                v46 = v41;                      // {93367D0F-35CE-C44E-8E38-BB33030C58B2}
                v48 = 0x33BB388E;
                v49 = 0xB2580C03;
                v50 = 4;
                v32 = RpeRegisterForStateNotification(&v57, &v45);
                v4 = v32;
                if ( v32 == STATUS_SUCCESS || v32 == -536182528 )
                {
                  v45 = 24;
                  v47 = 0x4EC435CE;
                  v46 = v31;                    // {93367D0F-35CE-C44E-8E38-BB33030C58B2}
                  v48 = 0x33BB388E;
                  v49 = 0xB2580C03;
                  v50 = 5;
                  v35 = RpeRegisterForStateNotification(&v57, &v45);
                  v4 = v35;
                  if ( v35 == STATUS_SUCCESS || v35 == -536182528 )
                  {
                    if ( dword_40FBB4 )
                    {
                      if ( (unsigned __int8)byte_40FBB8 >= 5u || !byte_40FBB8 )
                        EventWrite_01(
                          ETW_RegistrationHandle_02,
                          &stru_40E2F8,
                          (const _GUID *)"SMD initialized with RPE for Apps-Riva edge",
                          "SetupRPE",
                          "SMD initialized with RPE for Apps-Riva edge");
                    }
                    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
                    {
                      LODWORD(v39) = *((_DWORD *)off_40F178 + 4);
                      HIDWORD(v39) = *((_DWORD *)off_40F178 + 5);
                      DoTraceMessage_01(v39, 0x22u);
                    }
                    return 0;
                  }
                  else
                  {
                    if ( dword_40FBB4 && byte_40FBB8 != 1 )
                      EventWrite_02(
                        ETW_RegistrationHandle_02,
                        &stru_40E398,
                        (const _GUID *)"RpeRegisterForStateNotification for Apps-Riva edge failed",
                        "SetupRPE",
                        "RpeRegisterForStateNotification for Apps-Riva edge failed",
                        v35);
                    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                    {
                      v36 = *((unsigned __int8 *)off_40F178 + 29);
                      if ( v36 >= 2 )
                      {
                        LODWORD(v37) = *((_DWORD *)off_40F178 + 4);
                        HIDWORD(v37) = *((_DWORD *)off_40F178 + 5);
                        DoTraceMessage_02(v37, 0x21u, v36, v4);
                        return v4;
                      }
                    }
                  }
                }
                else
                {
                  if ( dword_40FBB4 && byte_40FBB8 != 1 )
                    EventWrite_02(
                      ETW_RegistrationHandle_02,
                      &stru_40E398,
                      (const _GUID *)"RpeRegisterForStateNotification for Apps-Riva edge failed",
                      "SetupRPE",
                      "RpeRegisterForStateNotification for Apps-Riva edge failed",
                      v32);
                  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                  {
                    v33 = *((unsigned __int8 *)off_40F178 + 29);
                    if ( v33 >= 2 )
                    {
                      LODWORD(v34) = *((_DWORD *)off_40F178 + 4);
                      HIDWORD(v34) = *((_DWORD *)off_40F178 + 5);
                      DoTraceMessage_02(v34, 0x20u, v33, v4);
                      return v4;
                    }
                  }
                }
              }
              else
              {
                if ( dword_40FBB4 && byte_40FBB8 != 1 )
                  EventWrite_02(
                    ETW_RegistrationHandle_02,
                    &stru_40E398,
                    (const _GUID *)"RpeSendState for Apps-Riva edge failed",
                    "SetupRPE",
                    "RpeSendState for Apps-Riva edge failed",
                    v28);
                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                {
                  v29 = *((unsigned __int8 *)off_40F178 + 29);
                  if ( v29 >= 2 )
                  {
                    LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
                    HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
                    DoTraceMessage_02(v30, 0x1Fu, v29, v4);
                    return v4;
                  }
                }
              }
            }
            else
            {
              if ( dword_40FBB4 && byte_40FBB8 != 1 )
                EventWrite_02(
                  ETW_RegistrationHandle_02,
                  &stru_40E398,
                  (const _GUID *)"RpeClientInit for Apps-Riva edge failed",
                  "SetupRPE",
                  "RpeClientInit for Apps-Riva edge failed",
                  inited);
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
              {
                v26 = *((unsigned __int8 *)off_40F178 + 29);
                if ( v26 >= 2 )
                {
                  LODWORD(v27) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v27) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_02(v27, 0x1Eu, v26, v4);
                  return v4;
                }
              }
            }
          }
          else
          {
            if ( dword_40FBB4 && byte_40FBB8 != 1 )
              EventWrite_02(
                ETW_RegistrationHandle_02,
                &stru_40E398,
                (const _GUID *)&ETW_RegistrationHandle_02,
                "SetupRPE",
                "RpeRegisterForStateNotification for Apps-Modem edge failed",
                v19);
            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
            {
              v20 = *((unsigned __int8 *)off_40F178 + 29);
              if ( v20 >= 2 )
              {
                LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v21, 0x1Cu, v20, v4);
                return v4;
              }
            }
          }
        }
        else
        {
          if ( dword_40FBB4 && byte_40FBB8 != 1 )
            EventWrite_02(
              ETW_RegistrationHandle_02,
              &stru_40E398,
              (const _GUID *)&ETW_RegistrationHandle_02,
              "SetupRPE",
              "RpeRegisterForStateNotification for Apps-Modem edge failed",
              v16);
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
          {
            v17 = *((unsigned __int8 *)off_40F178 + 29);
            if ( v17 >= 2 )
            {
              LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_02(v18, 0x1Bu, v17, v4);
              return v4;
            }
          }
        }
      }
      else
      {
        if ( dword_40FBB4 && byte_40FBB8 != 1 )
          EventWrite_02(
            ETW_RegistrationHandle_02,
            &stru_40E398,
            (const _GUID *)&ETW_RegistrationHandle_02,
            "SetupRPE",
            "RpeSendState for Apps-Modem edge failed",
            v13);
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
        {
          v14 = *((unsigned __int8 *)off_40F178 + 29);
          if ( v14 >= 2 )
          {
            LODWORD(v15) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v15) = *((_DWORD *)off_40F178 + 5);
            DoTraceMessage_02(v15, 0x1Au, v14, v4);
            return v4;
          }
        }
      }
    }
    else
    {
      if ( dword_40FBB4 && byte_40FBB8 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_02,
          &stru_40E398,
          (const _GUID *)&ETW_RegistrationHandle_02,
          "SetupRPE",
          "RpeClientInit for Apps-Modem edge failed",
          v10);
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v11 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v11 >= 2 )
        {
          LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v12, 0x19u, v11, v4);
          return v4;
        }
      }
    }
  }
  return v4;
}


// Function: EvtWdfIoQueueIoRead
void __fastcall EvtWdfIoQueueIoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
  WDFFILEOBJECT v4; // r0
  NTSTATUS v5; // r4
  unsigned __int64 v6; // r0
  SMD_PORT_CONTEXT *v7; // r0
  SMD_PORT_CONTEXT *v8; // r5
  unsigned __int64 v9; // r0
  int v10; // r3
  unsigned __int64 v11; // r0
  unsigned __int64 v12; // r0

  v4 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  if ( !v4 )
  {
    v5 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v6, 0x28u);
      WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_INVALID_DEVICE_REQUEST, 0);
      return;
    }
    goto LABEL_16;
  }
  v7 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                             WdfDriverGlobals,
                             v4,
                             WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v8 = v7;
  if ( !v7 )
  {
    v5 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v9, 0x29u);
      WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_INVALID_DEVICE_REQUEST, 0);
      return;
    }
    goto LABEL_16;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v10 = *(_DWORD *)&v7->field_0;
    LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v11, 0x2Au, v10);
  }
  v5 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, *(WDFQUEUE *)&v8->?);
  if ( v5 < 0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v12, 0x2Bu, *(_DWORD *)&v8->field_0);
    }
LABEL_16:
    WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, v5, 0);
    return;
  }
  WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, *(WDFWORKITEM *)&v8->field_74);
}


// Function: EvtWdfIoQueueIoReadHandler
// This function is the EvtWdfIoQueueIoRead callback handler. It processes read requests from the operating system, including validating the request, retrieving the SMD_PORT_CONTEXT, potentially preparing memory descriptors (MDLs), and completing the request.
NTSTATUS __fastcall sub_401D7C(int a1, WDFREQUEST Request)
{
  WDFREQUEST v2; // r5
  NT_STATUS_VALUES v3; // r6
  char *v4; // r10
  int v5; // r7
  WDFFILEOBJECT v6; // r0
  unsigned __int64 v7; // r0
  NTSTATUS result; // r0
  SMD_PORT_CONTEXT *v9; // r0
  SMD_PORT_CONTEXT *v10; // r4
  unsigned __int64 v11; // r0
  int v12; // r3
  unsigned __int64 v13; // r0
  _DWORD *v14; // r2
  unsigned __int64 v15; // r0
  int v16; // r3
  PVOID v17; // r5
  unsigned __int64 v18; // r0
  int v19; // r3
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0
  unsigned __int16 v22; // r2
  PIRP v23; // r0
  unsigned __int64 v24; // r0
  _MDL *MdlAddress; // r5
  _DWORD *v26; // r8
  unsigned int ByteCount; // r9
  char *v28; // r0
  int v29; // r3
  unsigned __int64 v30; // r0
  unsigned __int64 v31; // r0
  unsigned __int64 v32; // r0
  unsigned __int64 v33; // r0
  int v34; // r0
  int v35; // r5
  BOOL v36; // r3
  WDFSPINLOCK v37; // r1
  int v38; // r0
  unsigned __int64 v39; // r0
  unsigned __int64 v40; // r0
  unsigned __int64 v41; // r0
  WDFREQUEST v42; // r5
  WDFOBJECT i; // r5
  void *v44; // [sp+8h] [bp-30h] BYREF
  int v45; // [sp+Ch] [bp-2Ch] BYREF
  WDFREQUEST v46; // [sp+10h] [bp-28h]
  int v47; // [sp+14h] [bp-24h]

  v45 = 0;
  v2 = Request;
  v46 = Request;
  v3 = STATUS_SUCCESS;
  v4 = 0;
  v5 = 0;
  v6 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  if ( !v6 )
  {
    v3 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v7) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v7) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v7, 0x2Cu);
      return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v2,
               STATUS_INVALID_DEVICE_REQUEST,
               0);
    }
    return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, int))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v2,
             v3,
             v5);
  }
  v9 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                             WdfDriverGlobals,
                             v6,
                             WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v10 = v9;
  if ( !v9 )
  {
    v3 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v11, 0x2Du);
      return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v2,
               STATUS_INVALID_DEVICE_REQUEST,
               0);
    }
    return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, int))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v2,
             v3,
             v5);
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v12 = *(_DWORD *)&v9->field_0;
    LODWORD(v13) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v13) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v13, 0x2Eu, v12, *(_DWORD *)&v10->field_0);
  }
  if ( WdfFunctions.WdfObjectGetTypedContextWorker(WdfDriverGlobals, v2, WDF_SMD_REQUEST_CONTEXT_TYPE_INFO.UniqueType) )
    goto LABEL_16;
  v14 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
  {
    LODWORD(v15) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v15) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v15, 0x2Fu, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
LABEL_16:
    v14 = off_40F178;
  }
  v16 = *(_DWORD *)&v10->field_94;
  if ( *(_DWORD *)&v10->field_cc )
  {
    if ( v16 )
    {
      v4 = *(char **)&v10->field_a4;
      goto LABEL_65;
    }
    v23 = WdfFunctions.WdfRequestWdmGetIrp(WdfDriverGlobals, v2);
    if ( !v23 )
    {
      v3 = STATUS_IO_DEVICE_ERROR;
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v24) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v24) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v24, 0x33u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
      }
      goto LABEL_91;
    }
    MdlAddress = v23->MdlAddress;
    if ( MdlAddress )
    {
      v26 = 0;
      while ( 1 )
      {
        v47 = (int)MdlAddress->StartVa + MdlAddress->ByteOffset;
        if ( !v47 )
          break;
        ByteCount = MdlAddress->ByteCount;
        if ( !ByteCount )
        {
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
            DoTraceMessage_03(v30, 0x35u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, MdlAddress);
            v3 = STATUS_IO_DEVICE_ERROR;
            goto LABEL_91;
          }
          goto LABEL_28;
        }
        v3 = WdfFunctions.WdfMemoryCreateFromLookaside(WdfDriverGlobals, WDFLOOKASIDE_size_12, &v44);
        if ( v3 < STATUS_SUCCESS )
        {
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
            v22 = 54;
            goto LABEL_90;
          }
          goto LABEL_91;
        }
        v3 = WdfFunctions.WdfCollectionAdd(WdfDriverGlobals, v10->field_a8, v44);
        if ( v3 < STATUS_SUCCESS )
        {
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
            v22 = 55;
            goto LABEL_90;
          }
          goto LABEL_91;
        }
        v28 = (char *)WdfFunctions.WdfMemoryGetBuffer(WdfDriverGlobals, v44, 0);
        v29 = v47;
        *((_DWORD *)v28 + 1) = ByteCount;
        *((_DWORD *)v28 + 2) = v29;
        *(_DWORD *)v28 = 0;
        if ( v26 )
          *v26 = v28;
        else
          v4 = v28;
        MdlAddress = MdlAddress->Next;
        v26 = v28;
        if ( !MdlAddress )
        {
          *(_DWORD *)&v10->field_a4 = v4;
          v14 = off_40F178;
          goto LABEL_65;
        }
      }
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v31) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v31) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v31, 0x34u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, MdlAddress);
        v3 = STATUS_IO_DEVICE_ERROR;
        goto LABEL_91;
      }
    }
    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v32) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v32) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v32, 0x38u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
      v3 = STATUS_IO_DEVICE_ERROR;
      goto LABEL_91;
    }
LABEL_28:
    v3 = STATUS_IO_DEVICE_ERROR;
LABEL_91:
    v5 = 0;
LABEL_92:
    if ( *(_DWORD *)&v10->field_cc )
    {
      for ( i = WdfFunctions.WdfCollectionGetFirstItem(WdfDriverGlobals, v10->field_a8);
            i;
            i = WdfFunctions.WdfCollectionGetFirstItem(WdfDriverGlobals, v10->field_a8) )
      {
        WdfFunctions.WdfCollectionRemoveItem(WdfDriverGlobals, v10->field_a8, 0);
        WdfFunctions.WdfObjectDelete(WdfDriverGlobals, i);
      }
      v5 = 0;
    }
    v2 = v46;
    *(_DWORD *)&v10->field_94 = 0;
    *(_DWORD *)&v10->field_98 = 0;
    *(_DWORD *)&v10->field_9c = 0;
    *(_DWORD *)&v10->field_a0 = 0;
    *(_DWORD *)&v10->field_a4 = 0;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v2,
             v3,
             v5);
  }
  if ( v16 )
  {
    v4 = &v10->field_98;
    goto LABEL_65;
  }
  v3 = WdfFunctions.WdfRequestRetrieveOutputMemory(WdfDriverGlobals, v2, &v44);
  if ( v3 < STATUS_SUCCESS )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 2u )
      goto LABEL_91;
    LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
    v22 = 50;
LABEL_90:
    DoTraceMessage_03(v21, v22, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, v3);
    goto LABEL_91;
  }
  v17 = WdfFunctions.WdfMemoryGetBuffer(WdfDriverGlobals, v44, &v45);
  if ( !v17 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v20, 0x31u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
    }
    goto LABEL_28;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
  {
    LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_03(v18, 0x30u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, v45);
  }
  *(_DWORD *)&v10->field_98 = 0;
  v19 = v45;
  *(_DWORD *)&v10->field_a0 = v17;
  v4 = &v10->field_98;
  *(_DWORD *)&v10->field_9c = v19;
  v14 = off_40F178;
LABEL_65:
  if ( !v4 )
  {
    if ( (v14[8] & 2) != 0 && *((unsigned __int8 *)v14 + 29) >= 2u )
    {
      LODWORD(v33) = v14[4];
      HIDWORD(v33) = v14[5];
      DoTraceMessage_02(v33, 0x39u, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
      v3 = STATUS_IO_DEVICE_ERROR;
      goto LABEL_91;
    }
    goto LABEL_28;
  }
  WdfFunctions.WdfSpinLockAcquire(WdfDriverGlobals, v10->field_84);
  v34 = InterfaceFunction_03(*(_DWORD *)&v10->field_0, v4, 2);
  v35 = v34;
  v36 = !v34 || v34 == 0x80000000;
  v37 = v10->field_84;
  v38 = WdfDriverGlobals;
  *(_DWORD *)&v10->field_d0 = v36;
  WdfFunctions.WdfSpinLockRelease(v38, v37);
  if ( v35 && v35 != 0x80000000 )
  {
    if ( v35 >= 0 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v40) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v40) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v40, 0x3Du, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, v35);
      }
      v5 = v35;
      goto LABEL_92;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v39) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v39) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v39, 0x3Cu, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0, v35);
      v3 = STATUS_IO_DEVICE_ERROR;
      goto LABEL_91;
    }
    goto LABEL_28;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
  {
    LODWORD(v41) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v41) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v41, 0x3Au, *(_DWORD *)&v10->field_0, *(_DWORD *)&v10->field_0);
  }
  v42 = v46;
  result = WdfFunctions.WdfRequestRequeue(WdfDriverGlobals, v46);
  v3 = result;
  if ( result < STATUS_SUCCESS )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 2u )
      goto LABEL_91;
    LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
    v22 = 59;
    goto LABEL_90;
  }
  *(_DWORD *)&v10->field_94 = v42;
  return result;
}


// Function: EvtWdfIoQueueIoWrite
void __fastcall EvtWdfIoQueueIoWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
  WDFFILEOBJECT v5; // r0
  NTSTATUS v6; // r5
  unsigned __int64 v7; // r0
  SMD_PORT_CONTEXT *v8; // r0
  SMD_PORT_CONTEXT *v9; // r4
  unsigned __int64 v10; // r0
  int v11; // r3
  unsigned __int64 v12; // r0
  PIRP v13; // r0
  unsigned __int64 v14; // r0
  _MDL *MdlAddress; // r2
  unsigned __int64 v16; // r0
  unsigned int ByteCount; // r3
  size_t v18; // r3
  size_t v19; // r2
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0

  v5 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  if ( !v5 )
  {
    v6 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v7) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v7) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v7, 0x3Fu);
      WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_INVALID_DEVICE_REQUEST, 0);
      return;
    }
    goto LABEL_36;
  }
  v8 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                             WdfDriverGlobals,
                             v5,
                             WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v9 = v8;
  if ( !v8 )
  {
    v6 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v10, 0x40u);
      WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_INVALID_DEVICE_REQUEST, 0);
      return;
    }
    goto LABEL_36;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v11 = *(_DWORD *)&v8->field_0;
    LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v12, 0x41u, v11);
  }
  if ( *(_DWORD *)&v9->field_c8 )
  {
    if ( *(_DWORD *)&v9->field_cc )
    {
      Length = 0;
      v13 = WdfFunctions.WdfRequestWdmGetIrp(WdfDriverGlobals, Request);
      if ( !v13 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v14, 0x42u, *(_DWORD *)&v9->field_0);
        }
        goto LABEL_18;
      }
      MdlAddress = v13->MdlAddress;
      if ( !MdlAddress )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v16) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v16) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v16, 0x43u, *(_DWORD *)&v9->field_0);
          WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_IO_DEVICE_ERROR, 0);
          return;
        }
LABEL_18:
        WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, STATUS_IO_DEVICE_ERROR, 0);
        return;
      }
      do
      {
        ByteCount = MdlAddress->ByteCount;
        MdlAddress = MdlAddress->Next;
        Length += ByteCount;
      }
      while ( MdlAddress );
    }
    WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v9->field_90, 0);
    v18 = *(_DWORD *)&v9->field_4c;
    v19 = *(_DWORD *)&v9->field_54;
    *(_DWORD *)&v9->field_4c = v18 + Length;
    if ( v18 < v19 && v18 + Length >= v19 && *(_DWORD *)&v9->field_5c )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v20, 0x44u, *(_DWORD *)&v9->field_0);
      }
      KeSetEvent(*(_KEVENT **)&v9->field_5c, 0, FALSE);
    }
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v9->field_90);
  }
  v6 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, *(WDFQUEUE *)&v9->field_68);
  if ( v6 < 0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v21, 0x45u, *(_DWORD *)&v9->field_0);
    }
LABEL_36:
    WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, v6, 0);
    return;
  }
  if ( !*(_DWORD *)&v9->field_c8 )
    WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, *(WDFWORKITEM *)&v9->field_78);
}


// Function: EvtWdfIoQueueIoWriteHandler
// This function is the EvtWdfIoQueueIoWrite callback handler. It processes write requests from the operating system, including validating the request, retrieving the SMD_PORT_CONTEXT, potentially preparing memory descriptors (MDLs), writing data to the SMD FIFO via InterfaceFunction_05, and completing the request.
NTSTATUS __fastcall sub_4024FC(int a1, WDFREQUEST Request, int a3)
{
  WDFREQUEST v4; // r10
  NT_STATUS_VALUES v5; // r8
  int v6; // r6
  WDFFILEOBJECT v7; // r0
  unsigned __int64 v8; // r0
  NTSTATUS result; // r0
  SMD_PORT_CONTEXT *v10; // r0
  SMD_PORT_CONTEXT *v11; // r4
  unsigned __int64 v12; // r0
  int v13; // r3
  unsigned __int64 v14; // r0
  _DWORD *v15; // r2
  unsigned __int64 v16; // r0
  PIRP v17; // r0
  unsigned __int64 v18; // r0
  _MDL *MdlAddress; // r2
  unsigned __int64 v20; // r0
  unsigned int ByteCount; // r3
  NTSTATUS v22; // r0
  unsigned int v23; // r3
  unsigned int v24; // r2
  unsigned __int64 v25; // r0
  int v26; // r3
  PVOID v27; // r5
  unsigned __int64 v28; // r0
  int v29; // r3
  char *v30; // r9
  unsigned __int64 v31; // r0
  unsigned __int64 v32; // r0
  PIRP v33; // r0
  unsigned __int64 v34; // r0
  _MDL *v35; // r5
  _DWORD *v36; // r7
  int v37; // r10
  unsigned int v38; // r9
  char *v39; // r0
  unsigned __int64 v40; // r0
  WDFOBJECT i; // r5
  unsigned __int64 v42; // r0
  unsigned __int64 v43; // r0
  unsigned __int64 v44; // r0
  unsigned __int64 v45; // r0
  unsigned __int64 v46; // r0
  int v47; // r0
  int v48; // r5
  unsigned __int64 v49; // r0
  unsigned __int64 v50; // r0
  unsigned __int64 v51; // r0
  unsigned __int64 v52; // r0
  NTSTATUS v53; // [sp+4h] [bp-34h]
  void *v54; // [sp+8h] [bp-30h] BYREF
  int v55; // [sp+Ch] [bp-2Ch] BYREF
  char *v56; // [sp+10h] [bp-28h]
  WDFREQUEST v57; // [sp+14h] [bp-24h]

  v55 = 0;
  v56 = 0;
  v4 = Request;
  v57 = Request;
  v5 = STATUS_SUCCESS;
  v6 = 0;
  v7 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  if ( !v7 )
  {
    v5 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v8, 0x46u);
      return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v4,
               STATUS_INVALID_DEVICE_REQUEST,
               0);
    }
    return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, int))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v4,
             v5,
             v6);
  }
  v10 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                              WdfDriverGlobals,
                              v7,
                              WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v11 = v10;
  if ( !v10 )
  {
    v5 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v12, 0x47u);
      return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v4,
               STATUS_INVALID_DEVICE_REQUEST,
               0);
    }
    return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, int))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v4,
             v5,
             v6);
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v13 = *(_DWORD *)&v10->field_0;
    LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v14, 0x48u, v13, *(_DWORD *)&v11->field_0);
  }
  if ( WdfFunctions.WdfObjectGetTypedContextWorker(WdfDriverGlobals, v4, WDF_SMD_REQUEST_CONTEXT_TYPE_INFO.UniqueType) )
    goto LABEL_16;
  v15 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
  {
    LODWORD(v16) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v16) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v16, 0x49u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
LABEL_16:
    v15 = off_40F178;
  }
  if ( !*(_DWORD *)&v11->field_ac && *(_DWORD *)&v11->field_c8 )
  {
    if ( *(_DWORD *)&v11->field_cc )
    {
      a3 = 0;
      v17 = WdfFunctions.WdfRequestWdmGetIrp(WdfDriverGlobals, v4);
      if ( !v17 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v18, 0x4Au, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
        }
LABEL_24:
        v5 = STATUS_IO_DEVICE_ERROR;
        goto LABEL_72;
      }
      MdlAddress = v17->MdlAddress;
      if ( !MdlAddress )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v20, 0x4Bu, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
          v5 = STATUS_IO_DEVICE_ERROR;
          goto LABEL_72;
        }
        goto LABEL_24;
      }
      do
      {
        ByteCount = MdlAddress->ByteCount;
        MdlAddress = MdlAddress->Next;
        a3 += ByteCount;
      }
      while ( MdlAddress );
    }
    v22 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v11->field_90, 0);
    v23 = *(_DWORD *)&v11->field_4c;
    v24 = *(_DWORD *)&v11->field_50;
    v5 = v22;
    *(_DWORD *)&v11->field_4c = v23 - a3;
    if ( v23 > v24 && v23 - a3 <= v24 && v11->field_58 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v25) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v25) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v25, 0x4Cu, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v23 - a3);
      }
      KeSetEvent(v11->field_58, 0, FALSE);
    }
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v11->field_90);
    v15 = off_40F178;
  }
  v26 = *(_DWORD *)&v11->field_ac;
  if ( *(_DWORD *)&v11->field_cc )
  {
    if ( !v26 )
    {
      v33 = WdfFunctions.WdfRequestWdmGetIrp(WdfDriverGlobals, v4);
      if ( v33 )
      {
        v35 = v33->MdlAddress;
        if ( v35 )
        {
          v36 = 0;
          while ( 1 )
          {
            v37 = (int)v35->StartVa + v35->ByteOffset;
            if ( !v37 )
              break;
            v38 = v35->ByteCount;
            if ( !v38 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v43) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v43) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v43, 0x52u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v35);
              }
              goto LABEL_72;
            }
            v5 = WdfFunctions.WdfMemoryCreateFromLookaside(WdfDriverGlobals, WDFLOOKASIDE_size_12, &v54);
            if ( v5 < STATUS_SUCCESS )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v42) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v42) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v42, 0x53u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v5);
              }
              goto LABEL_72;
            }
            v5 = WdfFunctions.WdfCollectionAdd(WdfDriverGlobals, *(WDFCOLLECTION *)&v11->field_c0, v54);
            if ( v5 < STATUS_SUCCESS )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v40) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v40) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v40, 0x54u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v5);
              }
              goto LABEL_72;
            }
            v39 = (char *)WdfFunctions.WdfMemoryGetBuffer(WdfDriverGlobals, v54, 0);
            *(_DWORD *)v39 = 0;
            *((_DWORD *)v39 + 1) = v38;
            *((_DWORD *)v39 + 2) = v37;
            if ( v36 )
            {
              v30 = v56;
              *v36 = v39;
            }
            else
            {
              v30 = v39;
              v56 = v39;
            }
            v35 = v35->Next;
            v36 = v39;
            if ( !v35 )
            {
              v4 = v57;
              *(_DWORD *)&v11->field_bc = v30;
              v15 = off_40F178;
              goto LABEL_92;
            }
          }
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            LODWORD(v44) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v44) = *((_DWORD *)off_40F178 + 5);
            DoTraceMessage_03(v44, 0x51u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v35);
          }
        }
        else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v45) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v45) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v45, 0x55u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
        }
        goto LABEL_72;
      }
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v34) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v34) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v34, 0x50u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
        v5 = STATUS_IO_DEVICE_ERROR;
        goto LABEL_72;
      }
      goto LABEL_24;
    }
    v30 = *(char **)&v11->field_bc;
  }
  else if ( v26 )
  {
    v30 = &v11->field_b0;
  }
  else
  {
    v5 = WdfFunctions.WdfRequestRetrieveInputMemory(WdfDriverGlobals, v4, &v54);
    if ( v5 < STATUS_SUCCESS )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v32) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v32) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v32, 0x4Fu, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v5);
      }
      goto LABEL_72;
    }
    v27 = WdfFunctions.WdfMemoryGetBuffer(WdfDriverGlobals, v54, &v55);
    if ( !v27 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v31) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v31) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v31, 0x4Eu, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
      }
      goto LABEL_72;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v28) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v28) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v28, 0x4Du, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v55);
    }
    *(_DWORD *)&v11->field_b0 = 0;
    v29 = v55;
    *(_DWORD *)&v11->field_b8 = v27;
    v30 = &v11->field_b0;
    *(_DWORD *)&v11->field_b4 = v29;
    v15 = off_40F178;
  }
LABEL_92:
  if ( !v30 )
  {
    if ( (v15[8] & 2) != 0 && *((unsigned __int8 *)v15 + 29) >= 2u )
    {
      LODWORD(v46) = v15[4];
      HIDWORD(v46) = v15[5];
      DoTraceMessage_02(v46, 0x56u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
    }
    goto LABEL_72;
  }
  v47 = InterfaceFunction_05(*(_DWORD *)&v11->field_0, v30, 2);
  v48 = v47;
  if ( v47 && v47 != 0x80000000 )
  {
    if ( v47 >= 0 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v50) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v50) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v50, 0x5Au, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v48);
      }
      v6 = v48;
      goto LABEL_73;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v49) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v49) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v49, 0x59u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v48);
    }
    v5 = STATUS_IO_DEVICE_ERROR;
LABEL_72:
    v6 = 0;
LABEL_73:
    if ( *(_DWORD *)&v11->field_cc )
    {
      for ( i = WdfFunctions.WdfCollectionGetFirstItem(WdfDriverGlobals, *(_DWORD *)&v11->field_c0);
            i;
            i = WdfFunctions.WdfCollectionGetFirstItem(WdfDriverGlobals, *(_DWORD *)&v11->field_c0) )
      {
        WdfFunctions.WdfCollectionRemoveItem(WdfDriverGlobals, *(WDFCOLLECTION *)&v11->field_c0, 0);
        WdfFunctions.WdfObjectDelete(WdfDriverGlobals, i);
      }
      v6 = 0;
    }
    v4 = v57;
    *(_DWORD *)&v11->field_ac = 0;
    *(_DWORD *)&v11->field_b0 = 0;
    *(_DWORD *)&v11->field_b4 = 0;
    *(_DWORD *)&v11->field_b8 = 0;
    *(_DWORD *)&v11->field_bc = 0;
    return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
             WdfDriverGlobals,
             v4,
             v5,
             v6);
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
  {
    LODWORD(v51) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v51) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_03(v51, 0x57u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v48);
  }
  result = WdfFunctions.WdfRequestRequeue(WdfDriverGlobals, v4);
  v5 = result;
  if ( result < 0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      HIDWORD(v52) = *((_DWORD *)off_40F178 + 5);
      v53 = result;
      LODWORD(v52) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_03(v52, 0x58u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v53);
    }
    goto LABEL_72;
  }
  *(_DWORD *)&v11->field_ac = v4;
  return result;
}


// Function: EvtWdfIoQueueIoInternalDeviceControl
void __fastcall EvtWdfIoQueueIoInternalDeviceControl(
        WDFQUEUE Queue,
        WDFREQUEST Request,
        size_t OutputBufferLength,
        size_t InputBufferLength,
        ULONG IoControlCode)
{
  WDFFILEOBJECT v7; // r5
  int v8; // r7
  unsigned __int64 v9; // r0
  ULONG *v10; // r3
  NTSTATUS v11; // r2
  unsigned __int64 v12; // r0
  SMD_PORT_CONTEXT *v13; // r0
  SMD_PORT_CONTEXT *v14; // r5
  unsigned __int64 v15; // r0
  _DWORD *v16; // r4
  int v17; // r3
  unsigned __int64 v18; // r0
  unsigned __int64 v19; // r0
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0
  char **v22; // r7
  unsigned __int64 v23; // r0
  int v24; // r4
  unsigned __int64 v25; // r0
  unsigned __int64 v26; // r0
  unsigned int v27; // r2
  unsigned __int64 v28; // r0
  unsigned __int64 v29; // r0
  unsigned __int64 v30; // r0
  char *v31; // r3
  _DWORD *v32; // r2
  unsigned __int64 v33; // r0
  char *v34; // r3
  unsigned __int64 v35; // r0
  char *v36; // r3
  unsigned __int64 v37; // r0
  char v38; // r2
  char *v39; // r1
  int v40; // r3
  unsigned int v41; // r1
  int v42; // r0
  NTSTATUS v43; // r0
  unsigned __int64 v44; // r0
  unsigned __int64 v45; // r0
  unsigned __int64 v46; // r0
  unsigned __int64 v47; // r0
  unsigned __int64 v48; // r0
  WDFWAITLOCK v49; // r1
  int v50; // r0
  int v51; // r7
  unsigned __int64 v52; // r0
  WDFWAITLOCK v53; // r1
  _DWORD *v54; // r2
  unsigned __int64 v55; // r0
  unsigned __int64 v56; // r0
  NTSTATUS v57; // r0
  int v58; // r4
  unsigned __int64 v59; // r0
  unsigned __int64 v60; // r0
  unsigned __int64 v61; // r0
  unsigned __int64 v62; // r0
  unsigned __int64 v63; // r0
  unsigned __int64 v64; // r0
  const char **v65; // r4
  unsigned __int64 v66; // r0
  NTSTATUS v67; // r0
  const char *v68; // r2
  const char *v69; // r1
  unsigned __int64 v70; // r0
  unsigned __int64 v71; // r0
  unsigned __int64 v72; // r0
  unsigned __int16 v73; // r2
  unsigned __int64 v74; // r0
  unsigned __int64 v75; // r0
  unsigned __int64 v76; // r0
  const char **v77; // r4
  unsigned __int64 v78; // r0
  _DWORD *v79; // r2
  unsigned __int64 v80; // r0
  const char *v81; // r3
  unsigned __int64 v82; // r0
  unsigned __int64 v83; // r0
  unsigned __int64 v84; // r0
  unsigned __int64 v85; // r0
  unsigned __int64 v86; // r0
  unsigned __int64 v87; // r0
  unsigned __int64 v88; // r0
  int v89; // r7
  int v90; // r2
  unsigned __int64 v91; // r0
  int v92; // r0
  unsigned __int64 v93; // r0
  unsigned __int64 v94; // r0
  unsigned __int64 v95; // r0
  unsigned __int64 v96; // r0
  unsigned __int64 v97; // r0
  unsigned __int64 v98; // r0
  int v99; // r2
  unsigned __int64 v100; // r0
  unsigned __int64 v101; // r0
  int v102; // r6
  int v103; // r5
  unsigned int v104; // r3
  unsigned __int64 v105; // r0
  unsigned int v106; // r3
  unsigned __int64 v107; // r0
  int v108; // [sp+4h] [bp-84h]
  int v110; // [sp+10h] [bp-78h]
  const char **v111; // [sp+14h] [bp-74h] BYREF
  LONGLONG v112; // [sp+18h] [bp-70h] BYREF
  _DWORD v113[2]; // [sp+20h] [bp-68h] BYREF
  LONGLONG v114; // [sp+28h] [bp-60h] BYREF
  _WDF_OBJECT_ATTRIBUTES v115; // [sp+30h] [bp-58h] BYREF
  _DWORD v116[6]; // [sp+50h] [bp-38h] BYREF

  v111 = 0;
  v113[0] = 0;
  LODWORD(v112) = 0;
  v7 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  LODWORD(v114) = v7;
  if ( v7 )
  {
    if ( !WdfFunctions.WdfIoQueueGetDevice(WdfDriverGlobals, Queue) )
    {
      v8 = STATUS_INVALID_DEVICE_REQUEST;
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_01(v12, 0x5Du);
        v10 = 0;
        v11 = STATUS_INVALID_DEVICE_REQUEST;
        goto LABEL_277;
      }
LABEL_164:
      v10 = 0;
      v11 = v8;
      goto LABEL_277;
    }
    v13 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                WdfDriverGlobals,
                                v7,
                                WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
    v14 = v13;
    if ( !v13 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v15) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v15) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_01(v15, 0x5Eu);
      }
LABEL_13:
      v10 = 0;
      v11 = STATUS_INVALID_DEVICE_REQUEST;
      goto LABEL_277;
    }
    v16 = off_40F178;
    if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
    {
      v17 = *(_DWORD *)&v13->field_0;
      LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v18, 0x5Fu, v17, *(_DWORD *)&v14->field_0, IoControlCode);
      v16 = off_40F178;
    }
    if ( IoControlCode <= 0x2201F )
    {
      if ( IoControlCode != 0x2201F )
      {
        switch ( IoControlCode )
        {
          case 0x22003u:
            LODWORD(v112) = 0;
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v19) = v16[4];
              HIDWORD(v19) = v16[5];
              DoTraceMessage_02(v19, 0x60u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              v16 = off_40F178;
            }
            if ( !InputBufferLength )
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
              {
                LODWORD(v20) = v16[4];
                HIDWORD(v20) = v16[5];
                DoTraceMessage_02(v20, 0x61u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = STATUS_INVALID_PARAMETER;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v8 = WdfFunctions.WdfRequestRetrieveInputBuffer(WdfDriverGlobals, Request, 28, (PVOID *)&v111, v113);
            if ( v8 < STATUS_SUCCESS )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v21, 0x62u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v8);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v22 = (char **)v111;
            if ( !v111 )
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v23) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v23) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v23, 0x63u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = STATUS_INVALID_PARAMETER;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            if ( !*v111 || !strcmp(*v111, (const char *)&dword_40D3EC) )
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v47) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v47) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v47, 0x64u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = STATUS_INVALID_PARAMETER;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v24 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_90, 0);
            if ( *(_DWORD *)&v14->field_c4 )
            {
              v24 = STATUS_ACCESS_DENIED;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v25) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v25) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v25, 0x65u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              }
LABEL_97:
              WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v14->field_90);
              v10 = 0;
              v11 = v24;
              goto LABEL_277;
            }
            if ( *v22 && !strcmp(*v22, "LOOPBACK") && v22[1] )
            {
              v24 = STATUS_ACCESS_DENIED;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v26) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v26) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v26, 0x66u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              }
              goto LABEL_97;
            }
            v27 = (unsigned int)v22[2];
            if ( (v27 | 0x1F) != 0x1F )
            {
              v24 = STATUS_INVALID_PARAMETER;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v28) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v28) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v28, 0x67u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              }
              goto LABEL_97;
            }
            if ( (v27 & 4) != 0 )
              *(_DWORD *)&v14->field_c8 = 1;
            if ( ((unsigned int)v22[2] & 8) != 0 )
            {
              *(_DWORD *)&v14->field_cc = 1;
              v115.EvtCleanupCallback = NULL;
              v115.EvtDestroyCallback = NULL;
              v115.ContextSizeOverride = NULL;
              v115.ContextTypeInfo = NULL;
              v115.Size = 32;
              v115.ExecutionLevel = WdfExecutionLevelInheritFromParent;
              v115.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
              v115.ParentObject = (WDFOBJECT)v114;
              v24 = WdfFunctions.WdfCollectionCreate(WdfDriverGlobals, &v115, &v14->field_a8);
              if ( v24 < STATUS_SUCCESS )
              {
                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                {
                  LODWORD(v29) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v29) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_03(v29, 0x68u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v24);
                }
                goto LABEL_97;
              }
              v24 = WdfFunctions.WdfCollectionCreate(WdfDriverGlobals, &v115, &v14->field_c0);
              if ( v24 < STATUS_SUCCESS )
              {
                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                {
                  LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_03(v30, 0x69u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v24);
                }
                goto LABEL_97;
              }
            }
            if ( ((unsigned int)v22[2] & 2) != 0 )
              LODWORD(v112) = 4;
            v31 = v22[4];
            if ( v31 )
            {
              *(_DWORD *)&v14->field_4 = v31;
            }
            else
            {
              v32 = off_40F178;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 3u )
              {
LABEL_70:
                v34 = v22[5];
                if ( v34 )
                {
                  *(_DWORD *)&v14->field_8 = v34;
                }
                else
                {
                  if ( (v32[8] & 2) == 0 || *((unsigned __int8 *)v32 + 29) < 3u )
                  {
LABEL_76:
                    v36 = v22[6];
                    if ( v36 )
                    {
                      *(_DWORD *)&v14->field_c = v36;
                    }
                    else if ( (v32[8] & 2) != 0 && *((unsigned __int8 *)v32 + 29) >= 3u )
                    {
                      LODWORD(v37) = v32[4];
                      HIDWORD(v37) = v32[5];
                      DoTraceMessage_02(v37, 0x6Cu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                    }
                    v38 = v112;
                    *(_DWORD *)&v14->field_48 = v22[3];
                    v39 = *v22;
                    v116[0] = *(_DWORD *)*v22;
                    v116[1] = *((_DWORD *)v39 + 1);
                    v116[2] = *((_DWORD *)v39 + 2);
                    v116[3] = *((_DWORD *)v39 + 3);
                    v40 = *((_DWORD *)v39 + 4);
                    v41 = (unsigned int)v22[1];
                    v116[4] = v40;
                    v42 = InterfaceFunction_00(
                            (char *)v116,
                            v41,
                            v38,
                            (unsigned int)v22[3],
                            (int)SmdPortEventHandler,
                            v114);
                    if ( v42 )
                    {
                      *(_DWORD *)&v14->field_c4 = 1;
                      *(_DWORD *)&v14->field_0 = v42;
                      KeClearEvent((_KEVENT *)&v14->field_38);
                      if ( ((unsigned int)v22[2] & 0x10) != 0 )
                      {
                        v112 = 0;
                        v43 = KeWaitForSingleObject(&v14->field_18, Executive, KernelMode, TRUE, &v112);
                        v24 = v43;
                        if ( v43 )
                        {
                          if ( v43 == STATUS_TIMEOUT )
                          {
                            v24 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, v14->field_6c);
                            if ( v24 >= 0 )
                              goto LABEL_92;
                            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                            {
                              LODWORD(v45) = *((_DWORD *)off_40F178 + 4);
                              HIDWORD(v45) = *((_DWORD *)off_40F178 + 5);
                              DoTraceMessage_03(v45, 0x6Eu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v24);
                            }
                          }
                          else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0
                                 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                          {
                            LODWORD(v44) = *((_DWORD *)off_40F178 + 4);
                            HIDWORD(v44) = *((_DWORD *)off_40F178 + 5);
                            DoTraceMessage_03(v44, 0x6Fu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v24);
                          }
                        }
                      }
                    }
                    else
                    {
                      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                      {
                        LODWORD(v46) = *((_DWORD *)off_40F178 + 4);
                        HIDWORD(v46) = *((_DWORD *)off_40F178 + 5);
                        DoTraceMessage_02(v46, 0x6Du, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                      }
                      v24 = STATUS_IO_DEVICE_ERROR;
                    }
                    goto LABEL_97;
                  }
                  LODWORD(v35) = v32[4];
                  HIDWORD(v35) = v32[5];
                  DoTraceMessage_02(v35, 0x6Bu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                }
                v32 = off_40F178;
                goto LABEL_76;
              }
              LODWORD(v33) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v33) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_02(v33, 0x6Au, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            }
            v32 = off_40F178;
            goto LABEL_70;
          case 0x22007u:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v48) = v16[4];
              HIDWORD(v48) = v16[5];
              DoTraceMessage_02(v48, 0x70u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            }
            WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_90, 0);
            if ( *(_DWORD *)&v14->field_c4 )
            {
              v49 = v14->field_90;
              v50 = WdfDriverGlobals;
              *(_DWORD *)&v14->field_c4 = 0;
              WdfFunctions.WdfWaitLockRelease(v50, v49);
              WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, *(WDFWAITLOCK *)&v14->field_88, 0);
              WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, *(WDFWAITLOCK *)&v14->field_88);
              WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_8c, 0);
              WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v14->field_8c);
              WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_90, 0);
              v51 = InterfaceFunction_01(*(_DWORD *)&v14->field_0);
              if ( v51 < 0 )
              {
                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                {
                  LODWORD(v52) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v52) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_03(v52, 0x71u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v51);
                }
                v53 = v14->field_90;
                LODWORD(v112) = v51;
                WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v53);
                v10 = (ULONG *)v51;
                v11 = STATUS_IO_DEVICE_ERROR;
                goto LABEL_277;
              }
              v54 = off_40F178;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
              {
                LODWORD(v55) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v55) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v55, 0x72u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v54 = off_40F178;
              }
              if ( (v54[8] & 2) != 0 && *((unsigned __int8 *)v54 + 29) >= 5u )
              {
                LODWORD(v56) = v54[4];
                HIDWORD(v56) = v54[5];
                DoTraceMessage_02(v56, 0x73u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              }
              v114 = 0;
              v57 = KeWaitForSingleObject(&v14->field_28, Executive, KernelMode, 1u, &v114);
              v58 = v57;
              if ( v57 )
              {
                if ( v57 == 258 )
                {
                  v58 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, *(WDFQUEUE *)&v14->field_70);
                  if ( v58 >= 0 )
                  {
LABEL_92:
                    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v14->field_90);
                    return;
                  }
                  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                  {
                    LODWORD(v60) = *((_DWORD *)off_40F178 + 4);
                    HIDWORD(v60) = *((_DWORD *)off_40F178 + 5);
                    DoTraceMessage_03(v60, 0x74u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v58);
                  }
                }
                else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                {
                  LODWORD(v59) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v59) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_03(v59, 0x75u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v58);
                }
              }
            }
            else
            {
              v58 = -1073741436;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v61) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v61) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v61, 0x76u, 0, *(_DWORD *)&v14->field_0, -1073741436);
              }
            }
            WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v14->field_90);
            v10 = (ULONG *)v112;
            v11 = v58;
            goto LABEL_277;
          case 0x2200Bu:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v62) = v16[4];
              HIDWORD(v62) = v16[5];
              DoTraceMessage_02(v62, 0x77u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              v16 = off_40F178;
            }
            if ( !InputBufferLength )
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
              {
                LODWORD(v63) = v16[4];
                HIDWORD(v63) = v16[5];
                DoTraceMessage_02(v63, 0x78u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = STATUS_INVALID_PARAMETER;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v8 = WdfFunctions.WdfRequestRetrieveInputBuffer(WdfDriverGlobals, Request, 16, (PVOID *)&v111, v113);
            if ( v8 < 0 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v64) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v64) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v64, 0x79u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v8);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v65 = v111;
            if ( !v111 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v66) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v66) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v66, 0x7Au, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v67 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_90, 0);
            v68 = *v65;
            v8 = v67;
            if ( *v65 && (v69 = v65[1], v68 < v69) && (unsigned int)v69 <= *(_DWORD *)&v14->field_48 )
            {
              *(_DWORD *)&v14->field_50 = v68;
              *(_DWORD *)&v14->field_54 = v65[1];
              if ( v65[2] )
              {
                if ( v14->field_58
                  && (*((_DWORD *)off_40F178 + 8) & 2) != 0
                  && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
                {
                  LODWORD(v70) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v70) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_02(v70, 0x7Bu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                }
                v14->field_58 = (_KEVENT *)v65[2];
              }
              if ( v65[3] )
              {
                if ( v14->field_5c
                  && (*((_DWORD *)off_40F178 + 8) & 2) != 0
                  && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
                {
                  LODWORD(v71) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v71) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_02(v71, 0x7Cu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                }
                v14->field_5c = (_KEVENT *)v65[3];
              }
            }
            else
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v72) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v72) = *((_DWORD *)off_40F178 + 5);
                v73 = 125;
                goto LABEL_162;
              }
            }
            goto LABEL_163;
          case 0x2200Fu:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v74) = v16[4];
              HIDWORD(v74) = v16[5];
              DoTraceMessage_02(v74, 0x7Eu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              v16 = off_40F178;
            }
            if ( !InputBufferLength )
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
              {
                LODWORD(v75) = v16[4];
                HIDWORD(v75) = v16[5];
                DoTraceMessage_02(v75, 0x7Fu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = STATUS_INVALID_PARAMETER;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v8 = WdfFunctions.WdfRequestRetrieveInputBuffer(WdfDriverGlobals, Request, 8, (PVOID *)&v111, v113);
            if ( v8 < 0 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v76) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v76) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v76, 0x80u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v8);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v77 = v111;
            if ( !v111 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v78) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v78) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v78, 0x81u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
              goto LABEL_164;
            }
            v8 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v14->field_90, 0);
            if ( *v77 )
            {
              *(_DWORD *)&v14->field_10 = *v77;
            }
            else
            {
              v8 = STATUS_INVALID_PARAMETER;
              v79 = off_40F178;
              if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 2u )
                goto LABEL_186;
              LODWORD(v80) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v80) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_02(v80, 0x82u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            }
            v79 = off_40F178;
LABEL_186:
            v81 = v77[1];
            if ( v81 )
            {
              *(_DWORD *)&v14->field_14 = v81;
            }
            else
            {
              v8 = STATUS_INVALID_PARAMETER;
              if ( (v79[8] & 2) != 0 && *((unsigned __int8 *)v79 + 29) >= 2u )
              {
                LODWORD(v72) = v79[4];
                HIDWORD(v72) = v79[5];
                v73 = 131;
LABEL_162:
                DoTraceMessage_02(v72, v73, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              }
            }
LABEL_163:
            WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v14->field_90);
            goto LABEL_164;
          case 0x22013u:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v82) = v16[4];
              HIDWORD(v82) = v16[5];
              DoTraceMessage_02(v82, 0x99u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            }
            v8 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, *(WDFQUEUE *)&v14->gap60[4]);
            if ( v8 >= 0 )
            {
              WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, v14->field_74);
              return;
            }
            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
            {
              LODWORD(v83) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v83) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_03(v83, 0x9Au, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v8);
              v10 = 0;
              v11 = v8;
              goto LABEL_277;
            }
            goto LABEL_164;
          case 0x22017u:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v84) = v16[4];
              HIDWORD(v84) = v16[5];
              DoTraceMessage_02(v84, 0x9Bu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
              v16 = off_40F178;
            }
            if ( *(_DWORD *)&v14->field_c8 )
            {
              v8 = -1073741637;
              if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
              {
                LODWORD(v85) = v16[4];
                HIDWORD(v85) = v16[5];
                DoTraceMessage_02(v85, 0x9Cu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
                v10 = 0;
                v11 = -1073741637;
                goto LABEL_277;
              }
            }
            else
            {
              v8 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, v14->field_68);
              if ( v8 >= 0 )
              {
                WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, v14->field_78);
                return;
              }
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
              {
                LODWORD(v86) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v86) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_03(v86, 0x9Du, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v8);
                v10 = 0;
                v11 = v8;
                goto LABEL_277;
              }
            }
            goto LABEL_164;
          case 0x2201Bu:
            if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
            {
              LODWORD(v87) = v16[4];
              HIDWORD(v87) = v16[5];
              DoTraceMessage_02(v87, 0x9Eu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            }
            if ( !*(_DWORD *)&v14->field_c8 )
              goto LABEL_13;
            WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, v14->field_78);
            v10 = 0;
            goto LABEL_276;
          default:
            goto LABEL_246;
        }
      }
LABEL_221:
      v110 = 0;
      if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
      {
        LODWORD(v88) = v16[4];
        HIDWORD(v88) = v16[5];
        DoTraceMessage_02(v88, 0x84u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
        v16 = off_40F178;
      }
      switch ( IoControlCode )
      {
        case 0x2201Fu:
          v89 = 1;
          break;
        case 0x22023u:
          v89 = 1;
          v90 = 1;
          v110 = 1;
          goto LABEL_232;
        case 0x2202Bu:
          v90 = 1;
          v110 = 1;
          v89 = 0;
          goto LABEL_232;
        default:
          v89 = 0;
          break;
      }
      v90 = 0;
LABEL_232:
      if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 5u )
      {
        LODWORD(v91) = v16[4];
        HIDWORD(v91) = v16[5];
        DoTraceMessage_04(v91, v90, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v89, v90);
      }
      v92 = InterfaceFunction_08(*(_DWORD *)&v14->field_0, v110, v89);
      if ( v92 < 0 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          HIDWORD(v93) = *((_DWORD *)off_40F178 + 5);
          v108 = v92;
          LODWORD(v93) = *((_DWORD *)off_40F178 + 4);
          DoTraceMessage_03(v93, 0x86u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v108);
          v10 = 0;
          v11 = STATUS_IO_DEVICE_ERROR;
          goto LABEL_277;
        }
LABEL_271:
        v10 = 0;
        v11 = STATUS_IO_DEVICE_ERROR;
        goto LABEL_277;
      }
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v94) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v94) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v94, 0x87u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
      }
      v10 = 0;
      goto LABEL_276;
    }
    if ( IoControlCode > 0x2202F )
    {
      if ( IoControlCode != 139315 )
      {
        if ( IoControlCode == 139347 )
        {
          if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
          {
            LODWORD(v97) = v16[4];
            HIDWORD(v97) = v16[5];
            DoTraceMessage_02(v97, 0x8Cu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            v16 = off_40F178;
          }
          if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
          {
            LODWORD(v98) = v16[4];
            HIDWORD(v98) = v16[5];
            DoTraceMessage_02(v98, 0x90u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
            v11 = -1073741637;
            v10 = 0;
            goto LABEL_277;
          }
        }
        else
        {
          if ( IoControlCode != 139351 )
            goto LABEL_246;
          if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
          {
            LODWORD(v96) = v16[4];
            HIDWORD(v96) = v16[5];
            DoTraceMessage_02(v96, 0x98u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
          }
        }
        v11 = -1073741637;
        v10 = 0;
        goto LABEL_277;
      }
    }
    else if ( IoControlCode != 139311 )
    {
      if ( IoControlCode == 139299 || IoControlCode == 139303 || IoControlCode == 139307 )
        goto LABEL_221;
LABEL_246:
      v8 = -1073741637;
      if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 2u )
      {
        LODWORD(v95) = v16[4];
        HIDWORD(v95) = v16[5];
        DoTraceMessage_02(v95, 0x9Fu, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
        v10 = 0;
        v11 = -1073741637;
        goto LABEL_277;
      }
      goto LABEL_164;
    }
    v99 = 0;
    LODWORD(v112) = 0;
    if ( (v16[8] & 1) != 0 && *((unsigned __int8 *)v16 + 29) >= 4u )
    {
      LODWORD(v100) = v16[4];
      HIDWORD(v100) = v16[5];
      DoTraceMessage_02(v100, 0x88u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0);
      v16 = off_40F178;
      v99 = 0;
    }
    if ( IoControlCode == 139315 )
    {
      v99 = 1;
      LODWORD(v112) = 1;
    }
    if ( (v16[8] & 2) != 0 && *((unsigned __int8 *)v16 + 29) >= 5u )
    {
      LODWORD(v101) = v16[4];
      HIDWORD(v101) = v16[5];
      DoTraceMessage_03(v101, 0x89u, *(_DWORD *)&v14->field_0, *(_DWORD *)&v14->field_0, v99);
      v16 = off_40F178;
      v99 = v112;
    }
    v102 = *(_DWORD *)&v14->field_0;
    v103 = InterfaceFunction_09(*(_DWORD *)&v14->field_0, v99);
    if ( v103 < 0 )
    {
      if ( (v16[8] & 2) != 0 )
      {
        v104 = *((unsigned __int8 *)v16 + 29);
        if ( v104 >= 2 )
        {
          LODWORD(v105) = v16[4];
          HIDWORD(v105) = v16[5];
          DoTraceMessage_03(v105, 0x8Au, v104, v102, v103);
        }
      }
      goto LABEL_271;
    }
    if ( (v16[8] & 2) != 0 )
    {
      v106 = *((unsigned __int8 *)v16 + 29);
      if ( v106 >= 5 )
      {
        LODWORD(v107) = v16[4];
        HIDWORD(v107) = v16[5];
        DoTraceMessage_03(v107, 0x8Bu, v106, v102, v103);
      }
    }
    v10 = (ULONG *)v103;
LABEL_276:
    v11 = 0;
    goto LABEL_277;
  }
  v8 = STATUS_INVALID_DEVICE_REQUEST;
  if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 2u )
    goto LABEL_164;
  LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
  HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
  DoTraceMessage_01(v9, 0x5Cu);
  v10 = 0;
  v11 = STATUS_INVALID_DEVICE_REQUEST;
LABEL_277:
  WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, v11, v10);
}


// Function: EvtWdfIoQueueIoControlStatus
// This function is a WDF I/O queue handler for specific IOCTLs related to querying read/write buffer status and preparing memory for I/O operations. It handles 0x22013 (query read status and prepare output buffer) and 0x22017 (query write status).
int __fastcall sub_40388C(int a1, WDFREQUEST Request, int a3, int a4, int IoControlCode)
{
  NT_STATUS_VALUES v6; // r4
  unsigned int v7; // r9
  WDFFILEOBJECT v8; // r0
  unsigned __int64 v9; // r0
  SMD_PORT_CONTEXT *v10; // r0
  SMD_PORT_CONTEXT *v11; // r5
  unsigned __int64 v12; // r0
  _DWORD *v13; // r2
  int v14; // r3
  unsigned __int64 v15; // r0
  unsigned __int64 v16; // r0
  unsigned __int64 v17; // r0
  unsigned __int16 v18; // r2
  WDFREQUEST v19; // r7
  _DWORD *v20; // r2
  unsigned __int64 v21; // r0
  unsigned __int64 v22; // r0
  unsigned __int64 v23; // r0
  PIRP v24; // r0
  unsigned __int64 v25; // r0
  _MDL *MdlAddress; // r1
  _DWORD *v27; // r2
  unsigned __int64 v28; // r0
  unsigned __int64 v29; // r0
  unsigned __int64 v30; // r0
  _MDL *v32; // [sp+4h] [bp-2Ch]
  int v34; // [sp+Ch] [bp-24h] BYREF
  void *v35; // [sp+10h] [bp-20h] BYREF

  v6 = STATUS_SUCCESS;
  v34 = 0;
  v7 = 0;
  v8 = WdfFunctions.WdfRequestGetFileObject(WdfDriverGlobals, Request);
  if ( !v8 )
  {
    v6 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v9, 0xA0u);
    }
    goto LABEL_54;
  }
  v10 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                              WdfDriverGlobals,
                              v8,
                              WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v11 = v10;
  if ( !v10 )
  {
    v6 = STATUS_INVALID_DEVICE_REQUEST;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v12, 0xA1u);
    }
    goto LABEL_54;
  }
  v13 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v14 = *(_DWORD *)&v10->field_0;
    LODWORD(v15) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v15) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_03(v15, 0xA2u, v14, *(_DWORD *)&v11->field_0, IoControlCode);
    v13 = off_40F178;
  }
  if ( IoControlCode != 0x22013 )
  {
    if ( IoControlCode != 0x22017 )
    {
      v6 = STATUS_NOT_SUPPORTED;
      if ( (v13[8] & 2) != 0 && *((unsigned __int8 *)v13 + 29) >= 2u )
      {
        LODWORD(v16) = v13[4];
        HIDWORD(v16) = v13[5];
        DoTraceMessage_02(v16, 0xACu, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
      }
      goto LABEL_54;
    }
    v7 = InterfaceFunction_06(*(SMD_PORT_CONTEXT **)&v11->field_0);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 5u )
    {
LABEL_54:
      v19 = Request;
      return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, unsigned int))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v19,
               v6,
               v7);
    }
    LODWORD(v17) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v17) = *((_DWORD *)off_40F178 + 5);
    v18 = 171;
LABEL_53:
    DoTraceMessage_03(v17, v18, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v7);
    goto LABEL_54;
  }
  if ( !a3 )
  {
    v7 = InterfaceFunction_07(*(_DWORD *)&v11->field_0);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) == 0 || *((unsigned __int8 *)off_40F178 + 29) < 5u )
      goto LABEL_54;
    LODWORD(v17) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v17) = *((_DWORD *)off_40F178 + 5);
    v18 = 170;
    goto LABEL_53;
  }
  v19 = Request;
  if ( *(_DWORD *)&v11->field_cc )
  {
    v24 = WdfFunctions.WdfRequestWdmGetIrp(WdfDriverGlobals, Request);
    if ( !v24 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v25) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v25) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v25, 0xA6u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
        v6 = STATUS_IO_DEVICE_ERROR;
        return ((int (__fastcall *)(int, WDFREQUEST, NT_STATUS_VALUES, unsigned int))WdfFunctions.WdfRequestCompleteWithInformation)(
                 WdfDriverGlobals,
                 v19,
                 v6,
                 v7);
      }
      goto LABEL_35;
    }
    MdlAddress = v24->MdlAddress;
    if ( MdlAddress )
    {
      v27 = off_40F178;
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v28) = *((_DWORD *)off_40F178 + 4);
        v32 = MdlAddress;
        HIDWORD(v28) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v28, 0xA7u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v32);
        v27 = off_40F178;
      }
      if ( (v27[8] & 2) != 0 && *((unsigned __int8 *)v27 + 29) >= 2u )
      {
        LODWORD(v29) = v27[4];
        HIDWORD(v29) = v27[5];
        DoTraceMessage_02(v29, 0xA8u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
        v6 = STATUS_NOT_IMPLEMENTED;
        return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
                 WdfDriverGlobals,
                 v19,
                 v6,
                 v7);
      }
      goto LABEL_31;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v30, 0xA9u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, 0);
      v6 = STATUS_IO_DEVICE_ERROR;
      return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v19,
               v6,
               v7);
    }
    goto LABEL_35;
  }
  v6 = WdfFunctions.WdfRequestRetrieveOutputMemory(WdfDriverGlobals, Request, &v35);
  if ( v6 >= STATUS_SUCCESS )
  {
    if ( WdfFunctions.WdfMemoryGetBuffer(WdfDriverGlobals, v35, &v34) )
    {
      v20 = off_40F178;
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
      {
        LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_03(v21, 0xA3u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0, v34);
        v20 = off_40F178;
      }
      if ( (v20[8] & 2) != 0 && *((unsigned __int8 *)v20 + 29) >= 2u )
      {
        LODWORD(v22) = v20[4];
        HIDWORD(v22) = v20[5];
        DoTraceMessage_02(v22, 0xA4u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
      }
LABEL_31:
      v6 = STATUS_NOT_IMPLEMENTED;
      return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
               WdfDriverGlobals,
               v19,
               v6,
               v7);
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v23) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v23) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v23, 0xA5u, *(_DWORD *)&v11->field_0, *(_DWORD *)&v11->field_0);
    }
LABEL_35:
    v6 = STATUS_IO_DEVICE_ERROR;
  }
  return ((int (__fastcall *)(_DWORD, _DWORD, _DWORD, _DWORD))WdfFunctions.WdfRequestCompleteWithInformation)(
           WdfDriverGlobals,
           v19,
           v6,
           v7);
}


// Function: EvtWdfObjectContextCleanup
void __fastcall EvtWdfObjectContextCleanup(WDFOBJECT Object)
{
  unsigned __int64 v1; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    LODWORD(v1) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v1) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_01(v1, 0xC6u);
  }
}


// Function: EvtDriverUnload
void __fastcall EvtDriverUnload(WDFDRIVER Driver)
{
  unsigned __int64 v1; // r0
  _DEVICE_OBJECT *v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    LODWORD(v1) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v1) = *((_DWORD *)off_40F178 + 5);
    Driver = (WDFDRIVER)DoTraceMessage_01(v1, 0xC7u);
  }
  v2 = (_DEVICE_OBJECT *)McGenEventUnregister((unsigned __int64 *)Driver);
  WppCleanupKm(v2);
}


// Function: SmdPortEventHandler
// This function is a notification or event handler for SMD port-related events. It receives an event type and a port context, and based on the event type, it sets various kernel events and enqueues WDF work items.
SMD_PORT_CONTEXT *__fastcall SmdPortEventHandler(SMD_PORT_CONTEXT *result, int a2, void *a3)
{
  SMD_PORT_CONTEXT *v4; // r4
  unsigned int v5; // r3
  unsigned __int64 v6; // r0
  SMD_PORT_CONTEXT *v7; // r5
  unsigned int v8; // r3
  unsigned __int64 v9; // r0
  unsigned int v10; // r3
  unsigned __int64 v11; // r0
  _DWORD *v12; // r2
  unsigned int v13; // r3
  unsigned __int64 v14; // r0
  unsigned __int64 v15; // r0
  int v16; // r4
  unsigned __int64 v17; // r0
  unsigned __int64 v18; // r0
  unsigned __int64 v19; // r0
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0
  unsigned __int64 v22; // r0
  unsigned __int64 v23; // r0
  unsigned __int64 v24; // r0
  unsigned __int64 v25; // r0
  unsigned __int64 v26; // r0
  unsigned __int64 v27; // r0
  unsigned __int64 v28; // r0

  v4 = result;
  if ( a3 )
  {
    result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                   WdfDriverGlobals,
                                   a3,
                                   WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
    v7 = result;
    if ( result )
    {
      if ( !*(_DWORD *)&result->field_0 || *(SMD_PORT_CONTEXT **)&result->field_0 == v4 )
      {
        v12 = off_40F178;
        if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
        {
          v13 = *((unsigned __int8 *)off_40F178 + 29);
          if ( v13 >= 4 )
          {
            LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
            result = (SMD_PORT_CONTEXT *)DoTraceMessage_02(v14, 0xCBu, v13);
            v12 = off_40F178;
          }
        }
        switch ( a2 )
        {
          case 0:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v28) = v12[4];
              HIDWORD(v28) = v12[5];
              result = (SMD_PORT_CONTEXT *)DoTraceMessage_02(v28, 0xD8u, *(_DWORD *)&v7->field_0);
            }
            break;
          case 1:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v19) = v12[4];
              HIDWORD(v19) = v12[5];
              DoTraceMessage_02(v19, 0xCFu, *(_DWORD *)&v7->field_0);
            }
            KeSetEvent((_KEVENT *)&v7->field_18, 0, 0);
            result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, _DWORD))WdfFunctions.WdfWorkItemEnqueue)(
                                           WdfDriverGlobals,
                                           *(_DWORD *)&v7->field_7c);
            if ( *(_DWORD *)&v7->field_8 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
              {
                LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v20, 0xD0u, *(_DWORD *)&v7->field_0);
              }
              result = (SMD_PORT_CONTEXT *)KeSetEvent(*(_KEVENT **)&v7->field_8, 0, 0);
            }
            break;
          case 2:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v15) = v12[4];
              HIDWORD(v15) = v12[5];
              DoTraceMessage_02(v15, 0xCCu, *(_DWORD *)&v7->field_0);
            }
            ((void (__fastcall *)(int, WDFSPINLOCK, _DWORD *))WdfFunctions.WdfSpinLockAcquire)(
              WdfDriverGlobals,
              v7->field_84,
              v12);
            v16 = *(_DWORD *)&v7->field_d0;
            WdfFunctions.WdfSpinLockRelease(WdfDriverGlobals, v7->field_84);
            if ( !v16 && *(_DWORD *)&v7->field_4 )
            {
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
              {
                LODWORD(v17) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v17) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v17, 0xCDu, *(_DWORD *)&v7->field_0);
              }
              KeSetEvent(*(_KEVENT **)&v7->field_4, 0, 0);
            }
            result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, WDFWORKITEM))WdfFunctions.WdfWorkItemEnqueue)(
                                           WdfDriverGlobals,
                                           v7->field_74);
            break;
          case 3:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v18) = v12[4];
              HIDWORD(v18) = v12[5];
              DoTraceMessage_02(v18, 0xCEu, *(_DWORD *)&v7->field_0);
            }
            result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, WDFWORKITEM))WdfFunctions.WdfWorkItemEnqueue)(
                                           WdfDriverGlobals,
                                           v7->field_78);
            break;
          case 4:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v21) = v12[4];
              HIDWORD(v21) = v12[5];
              DoTraceMessage_02(v21, 0xD1u, *(_DWORD *)&v7->field_0);
            }
            KeSetEvent((_KEVENT *)&v7->field_28, 0, 0);
            result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, _DWORD))WdfFunctions.WdfWorkItemEnqueue)(
                                           WdfDriverGlobals,
                                           *(_DWORD *)&v7->field_80);
            break;
          case 5:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v24) = v12[4];
              HIDWORD(v24) = v12[5];
              result = (SMD_PORT_CONTEXT *)DoTraceMessage_02(v24, 0xD4u, *(_DWORD *)&v7->field_0);
              v12 = off_40F178;
            }
            if ( *(_DWORD *)&v7->field_10 )
            {
              if ( (v12[8] & 2) != 0 && *((unsigned __int8 *)v12 + 29) >= 5u )
              {
                LODWORD(v25) = v12[4];
                HIDWORD(v25) = v12[5];
                DoTraceMessage_02(v25, 0xD5u, *(_DWORD *)&v7->field_0);
              }
              result = (SMD_PORT_CONTEXT *)KeSetEvent(*(_KEVENT **)&v7->field_10, 0, 0);
            }
            break;
          case 6:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v26) = v12[4];
              HIDWORD(v26) = v12[5];
              result = (SMD_PORT_CONTEXT *)DoTraceMessage_02(v26, 0xD6u, *(_DWORD *)&v7->field_0);
              v12 = off_40F178;
            }
            if ( *(_DWORD *)&v7->field_14 )
            {
              if ( (v12[8] & 2) != 0 && *((unsigned __int8 *)v12 + 29) >= 5u )
              {
                LODWORD(v27) = v12[4];
                HIDWORD(v27) = v12[5];
                DoTraceMessage_02(v27, 0xD7u, *(_DWORD *)&v7->field_0);
              }
              result = (SMD_PORT_CONTEXT *)KeSetEvent(*(_KEVENT **)&v7->field_14, 0, 0);
            }
            break;
          case 9:
            if ( (v12[8] & 1) != 0 && *((unsigned __int8 *)v12 + 29) >= 4u )
            {
              LODWORD(v22) = v12[4];
              HIDWORD(v22) = v12[5];
              result = (SMD_PORT_CONTEXT *)DoTraceMessage_02(v22, 0xD2u, *(_DWORD *)&v7->field_0);
              v12 = off_40F178;
            }
            if ( *(_DWORD *)&v7->field_c )
            {
              if ( (v12[8] & 2) != 0 && *((unsigned __int8 *)v12 + 29) >= 5u )
              {
                LODWORD(v23) = v12[4];
                HIDWORD(v23) = v12[5];
                DoTraceMessage_02(v23, 0xD3u, *(_DWORD *)&v7->field_0);
              }
              result = (SMD_PORT_CONTEXT *)KeSetEvent(*(_KEVENT **)&v7->field_c, 0, 0);
            }
            break;
          default:
            return result;
        }
      }
      else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v10 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v10 >= 3 )
        {
          LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
          return (SMD_PORT_CONTEXT *)DoTraceMessage_03(v11, 0xCAu, v10);
        }
      }
    }
    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
    {
      v8 = *((unsigned __int8 *)off_40F178 + 29);
      if ( v8 >= 2 )
      {
        LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
        return (SMD_PORT_CONTEXT *)DoTraceMessage_02(v9, 0xC9u, v8);
      }
    }
  }
  else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
  {
    v5 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v5 >= 2 )
    {
      LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_02(v6, 0xC8u, v5);
    }
  }
  return result;
}


// Function: EvtWdfDevicePrepareHardware
NTSTATUS __fastcall EvtWdfDevicePrepareHardware(
        WDFDEVICE Device,
        WDFCMRESLIST ResourcesRaw,
        WDFCMRESLIST ResourcesTranslated)
{
  unsigned int v3; // r3
  unsigned __int64 v4; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 0;
  v3 = *((unsigned __int8 *)off_40F178 + 29);
  if ( v3 >= 4 )
  {
    HIDWORD(v4) = *((_DWORD *)off_40F178 + 5);
    LODWORD(v4) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_02(v4, 0xD9u, v3);
  }
  return 0;
}


// Function: EvtWdfDeviceReleaseHardware
NTSTATUS __fastcall EvtWdfDeviceReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  unsigned int v2; // r3
  unsigned __int64 v3; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 0;
  v2 = *((unsigned __int8 *)off_40F178 + 29);
  if ( v2 >= 4 )
  {
    HIDWORD(v3) = *((_DWORD *)off_40F178 + 5);
    LODWORD(v3) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_02(v3, 0xDAu, v2);
  }
  return 0;
}


// Function: EvtWdfDeviceSurpriseRemoval
void __fastcall __noreturn EvtWdfDeviceSurpriseRemoval(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v1 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v1 >= 4 )
    {
      HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_02(v2, 0xDDu, v1, Device);
    }
  }
  KeBugCheckEx(0x14Eu, (ULONG *)0x51736430, 0, 0, 0);
}


// Function: EvtWdfDeviceSelfManagedIoInit
NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoInit(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 0;
  v1 = *((unsigned __int8 *)off_40F178 + 29);
  if ( v1 >= 4 )
  {
    HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
    LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_02(v2, 0xDEu, v1);
  }
  return 0;
}


// Function: EvtWdfDeviceSelfManagedIoSuspend
NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoSuspend(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 0;
  v1 = *((unsigned __int8 *)off_40F178 + 29);
  if ( v1 >= 4 )
  {
    HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
    LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_02(v2, 0xDFu, v1);
  }
  return 0;
}


// Function: EvtWdfDeviceSelfManagedIoRestart
NTSTATUS __fastcall EvtWdfDeviceSelfManagedIoRestart(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 0;
  v1 = *((unsigned __int8 *)off_40F178 + 29);
  if ( v1 >= 4 )
  {
    HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
    LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_02(v2, 0xE0u, v1);
  }
  return 0;
}


// Function: EvtWdfDeviceSelfManagedIoFlush
void __fastcall EvtWdfDeviceSelfManagedIoFlush(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v1 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v1 >= 4 )
    {
      HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_02(v2, 0xE1u, v1);
    }
  }
}


// Function: EvtWdfDeviceSelfManagedIoCleanup
void __fastcall EvtWdfDeviceSelfManagedIoCleanup(WDFDEVICE Device)
{
  unsigned int v1; // r3
  unsigned __int64 v2; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v1 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v1 >= 4 )
    {
      HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_02(v2, 0xE2u, v1);
    }
  }
}


// Function: SmdProcessIoReadRequestsWorkItem
// This function is a WDF work item callback function responsible for processing pending I/O requests from a specific queue. It acts as a dispatcher, taking requests from a queue and forwarding them to the appropriate handlers (EvtWdfIoQueueIoReadHandler, EvtWdfIoQueueIoControlStatus) based on the request type. This is a common pattern for handling asynchronous I/O in WDF drivers. The queue it processes is likely the read queue.
SMD_PORT_CONTEXT *__fastcall SmdProcessIoReadRequestsWorkItem(void *a1)
{
  SMD_PORT_CONTEXT *result; // r0
  unsigned __int64 v2; // r0
  unsigned __int64 v3; // r0
  SMD_PORT_CONTEXT *v4; // r4
  unsigned __int64 v5; // r0
  _DWORD *v6; // r2
  int v7; // r3
  unsigned __int64 v8; // r0
  unsigned __int64 v9; // r0
  NTSTATUS v10; // r0
  WDFREQUEST v11; // r1
  unsigned __int64 v12; // r0
  unsigned __int64 v13; // r0
  unsigned __int64 v14; // r0
  int v15; // r0
  unsigned __int64 v16; // r0
  unsigned __int64 v17; // r0
  unsigned __int64 v18; // r0
  NTSTATUS v19; // r0
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0
  unsigned __int16 v22; // r2
  unsigned __int64 v23; // r0
  NTSTATUS v24; // [sp+4h] [bp-44h]
  NTSTATUS v25; // [sp+4h] [bp-44h]
  WDFREQUEST v26[2]; // [sp+8h] [bp-40h] BYREF
  _WDF_REQUEST_PARAMETERS v27; // [sp+10h] [bp-38h] BYREF

  result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 a1,
                                 WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
  if ( !result )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v2, 0xE3u);
    }
    return result;
  }
  if ( !*(_DWORD *)&result->field_0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v3) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v3) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v3, 0xE4u);
    }
    return result;
  }
  result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 *(_DWORD *)&result->field_0,
                                 WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v4 = result;
  if ( !result )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v5) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v5) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v5, 0xE5u);
    }
    return result;
  }
  v6 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v7 = *(_DWORD *)&result->field_0;
    LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v8, 0xE6u, v7, *(_DWORD *)&v4->field_0);
    v6 = off_40F178;
  }
  if ( (v6[8] & 2) != 0 && *((unsigned __int8 *)v6 + 29) >= 5u )
  {
    LODWORD(v9) = v6[4];
    HIDWORD(v9) = v6[5];
    DoTraceMessage_02(v9, 0xE7u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
  }
  WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v4->field_88, 0);
  if ( !*(_DWORD *)&v4->field_c4 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
      v22 = 234;
LABEL_71:
      DoTraceMessage_02(v21, v22, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
    }
    goto LABEL_72;
  }
  v10 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, *(WDFQUEUE *)&v4->gap60[4], v26);
  v11 = v26[0];
  if ( !v26[0] || v10 && v10 != STATUS_NO_MORE_ENTRIES )
  {
    if ( v10 && v10 != STATUS_NO_MORE_ENTRIES )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
        v24 = v10;
        LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
        DoTraceMessage_03(v12, 0xE8u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v24);
      }
LABEL_72:
      v26[0] = 0;
      goto LABEL_73;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v13) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v13) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v13, 0xE9u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
      v11 = v26[0];
    }
  }
  if ( v11 )
  {
    while ( 1 )
    {
      if ( !WdfFunctions.WdfObjectGetTypedContextWorker(
              WdfDriverGlobals,
              v11,
              WDF_SMD_REQUEST_CONTEXT_TYPE_INFO.UniqueType)
        && (*((_DWORD *)off_40F178 + 8) & 2) != 0
        && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
      {
        LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v14, 0xEBu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
      }
      *(_DWORD *)&v27.Size = 24;
      memset(&v27.Type, 0, 20);
      WdfFunctions.WdfRequestGetParameters(WdfDriverGlobals, v26[0], &v27);
      if ( v27.Type == WdfRequestTypeRead )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
        {
          LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
          v15 = DoTraceMessage_02(v18, 0xECu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
        }
        EvtWdfIoQueueIoReadHandler(v15, v26[0]);
      }
      else if ( v27.Type == WdfRequestTypeDeviceControlInternal )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
        {
          LODWORD(v17) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v17) = *((_DWORD *)off_40F178 + 5);
          v15 = DoTraceMessage_02(v17, 0xEDu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
        }
        EvtWdfIoQueueIoControlStatus(
          v15,
          v26[0],
          (int)v27.Parameters.Create.SecurityContext,
          v27.Parameters.DeviceIoControl.IoControlCode,
          v27.Parameters.DeviceIoControl.IoControlCode);
      }
      else
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v16) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v16) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_03(v16, 0xEEu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v27.Type);
        }
        WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v26[0], STATUS_INVALID_DEVICE_REQUEST);
      }
      if ( v4->field_94 )
        break;
      if ( !*(_DWORD *)&v4->field_c4 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
          v22 = 241;
          goto LABEL_71;
        }
        goto LABEL_72;
      }
      v19 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, *(WDFQUEUE *)&v4->gap60[4], v26);
      v11 = v26[0];
      if ( (!v26[0] || v19 && v19 != STATUS_NO_MORE_ENTRIES) && v19 && v19 != STATUS_NO_MORE_ENTRIES )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
          v25 = v19;
          LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
          DoTraceMessage_03(v20, 0xF0u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v25);
        }
        goto LABEL_72;
      }
      if ( !v26[0] )
        goto LABEL_73;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
      v22 = 239;
      goto LABEL_71;
    }
    goto LABEL_72;
  }
LABEL_73:
  result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, WDFWAITLOCK))WdfFunctions.WdfWaitLockRelease)(
                                 WdfDriverGlobals,
                                 v4->field_88);
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
  {
    LODWORD(v23) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v23) = *((_DWORD *)off_40F178 + 5);
    return (SMD_PORT_CONTEXT *)DoTraceMessage_02(v23, 0xF2u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
  }
  return result;
}


// Function: SmdProcessIoRequestsWorkItem
// This function is a WDF work item callback responsible for processing pending I/O requests from a specific queue. It acts as a dispatcher, taking requests from a queue and forwarding them to the appropriate handlers (EvtWdfIoQueueIoWriteHandler, EvtWdfIoQueueIoControlStatus) based on the request type.
SMD_PORT_CONTEXT *__fastcall sub_4044E4(void *a1)
{
  SMD_PORT_CONTEXT *result; // r0
  unsigned __int64 v2; // r0
  unsigned __int64 v3; // r0
  SMD_PORT_CONTEXT *v4; // r4
  unsigned __int64 v5; // r0
  _DWORD *v6; // r2
  int v7; // r3
  unsigned __int64 v8; // r0
  unsigned __int64 v9; // r0
  NTSTATUS v10; // r0
  WDFREQUEST *v11; // r1
  unsigned __int64 v12; // r0
  unsigned __int64 v13; // r0
  unsigned __int64 v14; // r0
  int v15; // r0
  unsigned __int64 v16; // r0
  unsigned __int64 v17; // r0
  unsigned __int64 v18; // r0
  NTSTATUS v19; // r0
  unsigned __int64 v20; // r0
  unsigned __int64 v21; // r0
  unsigned __int16 v22; // r2
  unsigned __int64 v23; // r0
  NTSTATUS v24; // [sp+4h] [bp-44h]
  NTSTATUS v25; // [sp+4h] [bp-44h]
  WDFREQUEST *v26; // [sp+8h] [bp-40h] BYREF
  _WDF_REQUEST_PARAMETERS v27; // [sp+10h] [bp-38h] BYREF

  result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 a1,
                                 WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
  if ( !result )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v2, 0xF3u);
    }
    return result;
  }
  if ( !*(_DWORD *)&result->field_0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v3) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v3) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v3, 0xF4u);
    }
    return result;
  }
  result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 *(_DWORD *)&result->field_0,
                                 WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v4 = result;
  if ( !result )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v5) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v5) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v5, 0xF5u);
    }
    return result;
  }
  v6 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v7 = *(_DWORD *)&result->field_0;
    LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v8, 0xF6u, v7, *(_DWORD *)&v4->field_0);
    v6 = off_40F178;
  }
  if ( (v6[8] & 2) != 0 && *((unsigned __int8 *)v6 + 29) >= 5u )
  {
    LODWORD(v9) = v6[4];
    HIDWORD(v9) = v6[5];
    DoTraceMessage_02(v9, 0xF7u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
  }
  WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, *(WDFWAITLOCK *)&v4->field_8c, 0);
  if ( !*(_DWORD *)&v4->field_c4 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
      v22 = 250;
LABEL_71:
      DoTraceMessage_02(v21, v22, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
    }
    goto LABEL_72;
  }
  v10 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, v4->field_68, (WDFREQUEST *)&v26);
  v11 = v26;
  if ( !v26 || v10 && v10 != STATUS_NO_MORE_ENTRIES )
  {
    if ( v10 && v10 != STATUS_NO_MORE_ENTRIES )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
        v24 = v10;
        LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
        DoTraceMessage_03(v12, 0xF8u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v24);
      }
LABEL_72:
      v26 = NULL;
      goto LABEL_73;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
    {
      LODWORD(v13) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v13) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v13, 0xF9u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
      v11 = v26;
    }
  }
  if ( v11 )
  {
    while ( 1 )
    {
      if ( !WdfFunctions.WdfObjectGetTypedContextWorker(
              WdfDriverGlobals,
              v11,
              WDF_SMD_REQUEST_CONTEXT_TYPE_INFO.UniqueType)
        && (*((_DWORD *)off_40F178 + 8) & 2) != 0
        && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v14, 0xFBu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
      }
      memset(&v27.MinorFunction, 0, 22);
      v27.Size = 24;
      WdfFunctions.WdfRequestGetParameters(WdfDriverGlobals, v26, &v27);
      if ( v27.Type == WdfRequestTypeWrite )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
        {
          LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
          v15 = DoTraceMessage_02(v18, 0xFCu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
        }
        EvtWdfIoQueueIoWriteHandler(v15, v26, (int)v27.Parameters.Create.SecurityContext);
      }
      else if ( v27.Type == WdfRequestTypeDeviceControlInternal )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
        {
          LODWORD(v17) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v17) = *((_DWORD *)off_40F178 + 5);
          v15 = DoTraceMessage_02(v17, 0xFDu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
        }
        EvtWdfIoQueueIoControlStatus(
          v15,
          v26,
          (int)v27.Parameters.Create.SecurityContext,
          v27.Parameters.DeviceIoControl.IoControlCode,
          v27.Parameters.DeviceIoControl.IoControlCode);
      }
      else
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v16) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v16) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_03(v16, 0xFEu, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v27.Type);
        }
        WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v26, STATUS_INVALID_DEVICE_REQUEST);
      }
      if ( *(_DWORD *)&v4->field_ac )
        break;
      if ( !*(_DWORD *)&v4->field_c4 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
          v22 = 257;
          goto LABEL_71;
        }
        goto LABEL_72;
      }
      v19 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, v4->field_68, (WDFREQUEST *)&v26);
      v11 = v26;
      if ( (!v26 || v19 && v19 != STATUS_NO_MORE_ENTRIES) && v19 && v19 != STATUS_NO_MORE_ENTRIES )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
        {
          v25 = v19;
          LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_03(v20, 0x100u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0, v25);
        }
        goto LABEL_72;
      }
      if ( !v26 )
        goto LABEL_73;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
      v22 = 255;
      goto LABEL_71;
    }
    goto LABEL_72;
  }
LABEL_73:
  result = (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, _DWORD))WdfFunctions.WdfWaitLockRelease)(
                                 WdfDriverGlobals,
                                 *(_DWORD *)&v4->field_8c);
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
  {
    LODWORD(v23) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v23) = *((_DWORD *)off_40F178 + 5);
    return (SMD_PORT_CONTEXT *)DoTraceMessage_02(v23, 0x102u, *(_DWORD *)&v4->field_0, *(_DWORD *)&v4->field_0);
  }
  return result;
}


// Function: SmdCompletePendingReadRequestsWorkItem
// This function is a WDF work item callback responsible for processing pending requests from a specific I/O queue and completing them. It's likely used to complete requests that were previously forwarded to a queue and are now ready to be finished.
__int64 __fastcall sub_404864(__int64 a1, int a2, int a3)
{
  #231 *v3; // r0
  unsigned __int64 v4; // r0
  unsigned __int64 v6; // r0
  SMD_PORT_CONTEXT *v7; // r0
  SMD_PORT_CONTEXT *v8; // r4
  unsigned __int64 v9; // r0
  int v10; // r3
  unsigned __int64 v11; // r0
  NTSTATUS v12; // r0
  unsigned __int64 v13; // r0
  __int64 v14; // [sp+0h] [bp-20h]
  _DWORD v15[2]; // [sp+8h] [bp-18h] BYREF

  v14 = a1;
  v15[1] = a3;
  v15[0] = 0;
  v3 = (#231 *)WdfFunctions.WdfObjectGetTypedContextWorker(
                 WdfDriverGlobals,
                 a1,
                 WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
  if ( v3 )
  {
    if ( *(_DWORD *)v3 )
    {
      v7 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 *(_DWORD *)v3,
                                 WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
      v8 = v7;
      if ( v7 )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
        {
          v10 = *(_DWORD *)&v7->field_0;
          LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
          LODWORD(v14) = *(_DWORD *)&v8->field_0;
          DoTraceMessage_02(v11, 0x106u, v10);
        }
        WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v8->field_90, 0);
        v12 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, v8->field_6c, (WDFREQUEST *)v15);
        if ( v12 && v12 != STATUS_NO_MORE_ENTRIES )
        {
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            HIDWORD(v14) = v12;
            LODWORD(v13) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v13) = *((_DWORD *)off_40F178 + 5);
            LODWORD(v14) = *(_DWORD *)&v8->field_0;
            DoTraceMessage_03(v13, 0x107u, *(_DWORD *)&v8->field_0);
          }
          v15[0] = 0;
        }
        WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v8->field_90);
        if ( v15[0] )
          WdfFunctions.WdfRequestComplete(WdfDriverGlobals, (WDFREQUEST)v15[0], 0);
      }
      else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_01(v9, 0x105u);
        return v14;
      }
    }
    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v6, 0x104u);
      return v14;
    }
  }
  else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
  {
    LODWORD(v4) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v4) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_01(v4, 0x103u);
    return v14;
  }
  return v14;
}


// Function: SmdCompletePendingWriteRequestsWorkItem
// This function is a WDF work item callback responsible for completing pending requests from a specific I/O queue and signaling an event. It's similar to SmdCompletePendingReadRequestsWorkItem but operates on a different queue, likely associated with write requests.
SMD_PORT_CONTEXT *__fastcall __spoils<R2,R3,R12,LR> sub_4049C4(void *a1)
{
  SMD_PORT_CONTEXT *result; // r0
  unsigned __int64 v2; // r0
  void *v3; // r8
  unsigned __int64 v4; // r0
  SMD_PORT_CONTEXT *v5; // r5
  unsigned __int64 v6; // r0
  int v7; // r3
  unsigned __int64 v8; // r0
  NTSTATUS v9; // r0
  unsigned __int64 v10; // r0
  WDFREQUEST v11; // [sp+8h] [bp-18h] BYREF

  v11 = 0;
  result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                 WdfDriverGlobals,
                                 a1,
                                 WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
  if ( result )
  {
    v3 = *(void **)&result->field_0;
    if ( *(_DWORD *)&result->field_0 )
    {
      result = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                     WdfDriverGlobals,
                                     v3,
                                     WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
      v5 = result;
      if ( result )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
        {
          v7 = *(_DWORD *)&result->field_0;
          LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v8, 0x10Bu, v7, *(_DWORD *)&v5->field_0);
        }
        WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v5->field_90, 0);
        v9 = WdfFunctions.WdfIoQueueRetrieveNextRequest(WdfDriverGlobals, v5->field_70, &v11);
        if ( v9 && v9 != STATUS_NO_MORE_ENTRIES )
        {
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
          {
            HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
            LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
            DoTraceMessage_03(v10, 0x10Cu, *(_DWORD *)&v5->field_0, *(_DWORD *)&v5->field_0);
          }
          v11 = 0;
        }
        WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v5->field_90);
        WdfFunctions.WdfObjectDereferenceActual(WdfDriverGlobals, v3, 0, 4812, ".\\wdf\\driver.c");
        result = (SMD_PORT_CONTEXT *)KeSetEvent((_KEVENT *)&v5->field_38, 0, 0);
        if ( v11 )
          return (SMD_PORT_CONTEXT *)((int (__fastcall *)(int, WDFREQUEST, _DWORD))WdfFunctions.WdfRequestComplete)(
                                       WdfDriverGlobals,
                                       v11,
                                       0);
      }
      else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
        return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v6, 0x10Au);
      }
    }
    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v4) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v4) = *((_DWORD *)off_40F178 + 5);
      return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v4, 0x109u);
    }
  }
  else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
  {
    LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
    return (SMD_PORT_CONTEXT *)DoTraceMessage_01(v2, 0x108u);
  }
  return result;
}


// Function: EvtWdfIoQueueIoStop
void __fastcall EvtWdfIoQueueIoStop(WDFQUEUE Queue, WDFREQUEST Request, ULONG ActionFlags)
{
  _DWORD *v5; // r4
  unsigned int v6; // r3
  unsigned __int64 v7; // r0
  unsigned int v8; // r3
  unsigned __int64 v9; // r0
  unsigned int v10; // r3
  unsigned __int64 v11; // r0
  unsigned int v12; // r3
  unsigned __int64 v13; // r0

  v5 = off_40F178;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v6 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v6 >= 4 )
    {
      LODWORD(v7) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v7) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v7, 0x10Eu, v6);
      v5 = off_40F178;
    }
  }
  if ( (ActionFlags & 0x10000000) != 0 )
  {
    if ( (v5[8] & 2) != 0 )
    {
      v8 = *((unsigned __int8 *)v5 + 29);
      if ( v8 >= 5 )
      {
        LODWORD(v9) = v5[4];
        HIDWORD(v9) = v5[5];
        DoTraceMessage_02(v9, 0x10Fu, v8);
      }
    }
    if ( WdfFunctions.WdfRequestUnmarkCancelable(WdfDriverGlobals, Request) )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v10 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v10 >= 2 )
        {
          LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v11, 0x110u, v10);
        }
      }
    }
    else
    {
      WdfFunctions.WdfRequestComplete(WdfDriverGlobals, Request, STATUS_CANCELLED);
    }
  }
  else if ( (v5[8] & 2) != 0 )
  {
    v12 = *((unsigned __int8 *)v5 + 29);
    if ( v12 >= 2 )
    {
      LODWORD(v13) = v5[4];
      HIDWORD(v13) = v5[5];
      DoTraceMessage_02(v13, 0x111u, v12);
    }
  }
}


// Function: EvtWdfIoQueueIoCanceledOnQueue
void __fastcall EvtWdfIoQueueIoCanceledOnQueue(WDFQUEUE Queue, WDFREQUEST Request)
{
  unsigned int v3; // r3
  unsigned __int64 v4; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v3 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v3 >= 4 )
    {
      HIDWORD(v4) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v4) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_03(v4, 0x112u, v3);
    }
  }
  WdfFunctions.WdfRequestComplete(WdfDriverGlobals, Request, STATUS_CANCELLED);
}


// Function: SmdModemStateNotificationCallback
void *__fastcall SmdModemStateNotificationCallback(void *result, int a2, _DWORD *a3)
{
  void *v5; // r7
  unsigned int v6; // r3
  unsigned __int64 v7; // r0
  int v8; // r3
  unsigned __int64 v9; // r0
  unsigned __int64 v10; // r0
  unsigned __int64 v11; // r0
  int v12; // r4
  unsigned int v13; // r3
  unsigned __int64 v14; // r0
  SMD_SSR_WORKITEM_CONTEXT *v15; // r4
  int v16; // r3
  int v17; // r0
  unsigned int v18; // r3
  unsigned __int64 v19; // r0
  void *v20; // [sp+10h] [bp-78h] BYREF
  _WDF_WORKITEM_CONFIG v21; // [sp+18h] [bp-70h] BYREF
  _WDF_OBJECT_ATTRIBUTES v22; // [sp+28h] [bp-60h] BYREF
  _DWORD buffer2[4]; // [sp+48h] [bp-40h] BYREF
  _DWORD v24[4]; // [sp+58h] [bp-30h] BYREF

  v5 = result;
  buffer2[0] = -1821522431;
  buffer2[1] = 1266832688;
  buffer2[2] = -1536021859;
  buffer2[3] = -1043874168;
  v24[0] = -1825145585;
  v24[1] = 1321481678;
  v24[2] = 867907726;
  v24[3] = -1302852605;
  if ( !a2 || !result || !a3 )
  {
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      result = (void *)EventWrite_02(
                         ETW_RegistrationHandle_02,
                         &stru_40E398,
                         (const _GUID *)&ETW_RegistrationHandle_02,
                         "SmdModemStateNotificationCallback",
                         "Invalid parameter received from RPE callback",
                         STATUS_INVALID_PARAMETER);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
    {
      v18 = *((unsigned __int8 *)off_40F178 + 29);
      if ( v18 >= 2 )
      {
        LODWORD(v19) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v19) = *((_DWORD *)off_40F178 + 5);
        return (void *)DoTraceMessage_02(v19, 0x113u, v18, STATUS_INVALID_PARAMETER);
      }
    }
    return result;
  }
  result = (void *)memcmp((const void *)(a2 + 4), buffer2, 0x10u);
  if ( result )
  {
    result = (void *)memcmp((const void *)(a2 + 4), v24, 0x10u);
    if ( result )
    {
      if ( dword_40FBB4 && byte_40FBB8 != 1 )
        result = (void *)EventWrite_02(
                           ETW_RegistrationHandle_02,
                           &stru_40E398,
                           (const _GUID *)&ETW_RegistrationHandle_02,
                           "SmdModemStateNotificationCallback",
                           "RPE Notification received for unregistered module",
                           STATUS_INVALID_PARAMETER);
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v6 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v6 >= 2 )
        {
          LODWORD(v7) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v7) = *((_DWORD *)off_40F178 + 5);
          return (void *)DoTraceMessage_02(v7, 0x114u, v6, STATUS_INVALID_PARAMETER);
        }
      }
      return result;
    }
  }
  v8 = *(_DWORD *)(a2 + 20);
  if ( v8 == 4 )
  {
    *(_DWORD *)&v21.AutomaticSerialization = 1;
    v21.Size = 12;
    v21.EvtWorkItemFunc = (void (__fastcall *)(WDFWORKITEM *))SmdEvtWorkItemModemStateNotification;
    v22.EvtCleanupCallback = NULL;
    v22.EvtDestroyCallback = NULL;
    v22.ContextSizeOverride = NULL;
    v22.Size = 32;
    v22.ExecutionLevel = WdfExecutionLevelInheritFromParent;
    v22.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
    v22.ContextTypeInfo = (_WDF_OBJECT_CONTEXT_TYPE_INFO *)WDF_SMD_SSR_WORKITEM_CONTEXT_TYPE_INFO.UniqueType;
    v22.ParentObject = v5;
    result = (void *)WdfFunctions.WdfWorkItemCreate(WdfDriverGlobals, &v21, &v22, &v20);
    v12 = (int)result;
    if ( (int)result < 0 )
    {
      if ( dword_40FBB4 && byte_40FBB8 != 1 )
        result = (void *)EventWrite_02(
                           ETW_RegistrationHandle_02,
                           &stru_40E3B8,
                           (const _GUID *)&ETW_RegistrationHandle_02,
                           "SmdModemStateNotificationCallback",
                           "WdfWorkItemCreate",
                           result);
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v13 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v13 >= 2 )
        {
          LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
          return (void *)DoTraceMessage_02(v14, 0x115u, v13, v12);
        }
      }
      return result;
    }
    v15 = (SMD_SSR_WORKITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                        WdfDriverGlobals,
                                        v20,
                                        WDF_SMD_SSR_WORKITEM_CONTEXT_TYPE_INFO.UniqueType);
    if ( !memcmp((const void *)(a2 + 4), buffer2, 0x10u) )
    {
      v15->field_0.Data1 = 0xF9D15453;
      *(_DWORD *)&v15->field_0.Data2 = 0x434C8335;
      *(_DWORD *)v15->field_0.Data4 = 0xD9FC72AA;
      *(_DWORD *)&v15->field_0.Data4[4] = 0xF335F125;
      v16 = 1;
    }
    else
    {
      if ( memcmp((const void *)(a2 + 4), v24, 0x10u) )
      {
LABEL_41:
        v17 = WdfDriverGlobals;
        *(_DWORD *)&v15->field_14 = 4;
        *(_DWORD *)&v15->field_18 = v5;
        return (void *)((int (__fastcall *)(int, void *))WdfFunctions.WdfWorkItemEnqueue)(v17, v20);
      }
      v15->field_0.Data1 = 0xD30F94E9;
      *(_DWORD *)&v15->field_0.Data2 = 0x4ED59C90;
      *(_DWORD *)v15->field_0.Data4 = 0x669204AE;
      *(_DWORD *)&v15->field_0.Data4[4] = 0x21477C27;
      v16 = 8;
    }
    *(_DWORD *)&v15->field_10 = v16;
    goto LABEL_41;
  }
  if ( v8 == 5 )
  {
    result = (void *)memcmp((const void *)(a2 + 4), buffer2, 0x10u);
    if ( result )
    {
      result = (void *)memcmp((const void *)(a2 + 4), v24, 0x10u);
      if ( !result && (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
      {
        LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
        result = (void *)DoTraceMessage_01(v11, 0x117u);
      }
    }
    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
    {
      LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
      result = (void *)DoTraceMessage_01(v10, 0x116u);
      *a3 = 5;
      return result;
    }
    *a3 = 5;
  }
  else
  {
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      result = (void *)EventWrite_02(
                         ETW_RegistrationHandle_02,
                         &stru_40E398,
                         (const _GUID *)&ETW_RegistrationHandle_02,
                         "SmdModemStateNotificationCallback",
                         "Notification callback from RPE for invalid state",
                         STATUS_INVALID_PARAMETER);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
      return (void *)DoTraceMessage_05(v9, 0x118u, &WPP_Traceguids_01, *(_DWORD *)(a2 + 20));
    }
  }
  return result;
}


// Function: SmdAlwaysTrueStatus
// This function is a simple status or flag checking function, possibly related to tracing or debugging. It always returns 1, but it might have side effects of logging a message based on certain global flags.
int sub_405078()
{
  unsigned __int64 v0; // r0

  if ( (*((_DWORD *)off_40F178 + 8) & 1) == 0 )
    return 1;
  if ( *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    LODWORD(v0) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v0) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_01(v0, 0x119u);
  }
  return 1;
}


// Function: SmdEvtWorkItemModemStateNotification
void __fastcall SmdEvtWorkItemModemStateNotification(void *a1)
{
  unsigned __int64 v2; // r0
  SMD_SSR_WORKITEM_CONTEXT *result; // r0
  SMD_SSR_WORKITEM_CONTEXT *v4; // r4
  unsigned int v5; // r3
  unsigned __int64 v6; // r0
  int v7; // r0
  int v8; // r4
  unsigned int v9; // r3
  unsigned __int64 v10; // r0
  int v11; // [sp+10h] [bp-30h] BYREF
  unsigned int Data1; // [sp+14h] [bp-2Ch]
  int v13; // [sp+18h] [bp-28h]
  int v14; // [sp+1Ch] [bp-24h]
  int v15; // [sp+20h] [bp-20h]
  int v16; // [sp+24h] [bp-1Ch]

  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    LODWORD(v2) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v2) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_01(v2, 0x11Au);
  }
  result = (SMD_SSR_WORKITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                         WdfDriverGlobals,
                                         a1,
                                         WDF_SMD_SSR_WORKITEM_CONTEXT_TYPE_INFO.UniqueType);
  v4 = result;
  if ( result )
  {
    if ( *(_DWORD *)&result->field_14 == 4 )
      SmdProcessChannelCleanup(*(_DWORD *)&result->field_10);
    Data1 = 0;
    v13 = 0;
    v14 = 0;
    v15 = 0;
    v16 = 0;
    v11 = 24;
    Data1 = v4->field_0.Data1;
    v13 = *(_DWORD *)&v4->field_0.Data2;
    v14 = *(_DWORD *)v4->field_0.Data4;
    v15 = *(_DWORD *)&v4->field_0.Data4[4];
    v16 = 4;
    v7 = RpeSendState(&v11);
    v8 = v7;
    if ( v7 && v7 != -536182528 )
    {
      if ( dword_40FBB4 && byte_40FBB8 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_02,
          &stru_40E398,
          (const _GUID *)&ETW_RegistrationHandle_02,
          "SmdEvtWorkItemModemStateNotification",
          "RpeSendState failed",
          v7);
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v9 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v9 >= 2 )
        {
          LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v10, 0x11Cu, v9, v8);
        }
      }
    }
    WdfFunctions.WdfObjectDelete(WdfDriverGlobals, a1);
  }
  else
  {
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      EventWrite_03(
        ETW_RegistrationHandle_02,
        &stru_40E160,
        (const _GUID *)&ETW_RegistrationHandle_02,
        "SmdEvtWorkItemModemStateNotification",
        "SSR workitem context ",
        a1,
        STATUS_UNSUCCESSFUL);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
    {
      v5 = *((unsigned __int8 *)off_40F178 + 29);
      if ( v5 >= 2 )
      {
        LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v6, 0x11Bu, v5, STATUS_UNSUCCESSFUL);
      }
    }
  }
}


// Function: DoTraceMessage_07
int __fastcall DoTraceMessage_07(unsigned int a1, unsigned int a2)
{
  size_t v4; // r0
  int v6; // [sp+18h] [bp-10h] BYREF

  v6 = 307;
  v4 = strlen("smd_event_send");
  return pfnWppTraceMessage(__PAIR64__(a2, a1), 0x2Bu, &WPP_Traceguids_02, 0xBu, "smd_event_send", v4 + 1, &v6, 4, 0);
}


// Function: SmdInitializeSmsmCommunication
// This function is a WDF work item callback responsible for initializing and communicating with the "SMSM" (Shared Memory Service Module) device. It creates and opens an I/O target to the \Device\SMSM device and then sends a synchronous IOCTL to it.
NTSTATUS __fastcall sub_4052B8(WDFWORKITEM a1)
{
  WDFOBJECT v1; // r0
  WDFIOTARGET v2; // r1
  NTSTATUS result; // r0
  NTSTATUS v4; // r0
  _WDF_MEMORY_DESCRIPTOR v5; // [sp+10h] [bp-D0h] BYREF
  _WDF_OBJECT_ATTRIBUTES v6; // [sp+20h] [bp-C0h] BYREF
  int v7; // [sp+40h] [bp-A0h]
  _BYTE v8[8]; // [sp+48h] [bp-98h] BYREF
  _WDF_IO_TARGET_OPEN_PARAMS dest; // [sp+50h] [bp-90h] BYREF
  _DWORD v10[4]; // [sp+98h] [bp-48h] BYREF
  wchar_t v11[16]; // [sp+A8h] [bp-38h] BYREF

  v1 = WdfFunctions.WdfWorkItemGetParentObject(WdfDriverGlobals, a1);
  v6.EvtCleanupCallback = NULL;
  v6.EvtDestroyCallback = NULL;
  v6.ContextSizeOverride = NULL;
  v6.ContextTypeInfo = NULL;
  v2 = WDFIOTARGET_SMSM;
  v6.Size = 32;
  v6.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v6.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v6.ParentObject = v1;
  if ( WDFIOTARGET_SMSM )
    goto WDFIOTARGET_SMSM_ALREADY_SET;
  wcscpy(v11, L"\\Device\\SMSM");
  v7 = 1703960;
  result = WdfFunctions.WdfIoTargetCreate(WdfDriverGlobals, v1, &v6, &WDFIOTARGET_SMSM);
  if ( result < 0 )
    return result;
  memset(&dest, 0, sizeof(dest));
  dest.Size = 72;
  dest.Type = WdfIoTargetOpenByName;
  *(_DWORD *)&dest.TargetDeviceName.Length = v7;
  dest.DesiredAccess = 2031616;
  dest.CreateOptions = 64;
  dest.CreateDisposition = 1;
  dest.TargetDeviceName.Buffer = v11;
  v4 = ((int (__fastcall *)(int, WDFIOTARGET, _WDF_IO_TARGET_OPEN_PARAMS *))WdfFunctions.WdfIoTargetOpen)(
         WdfDriverGlobals,
         WDFIOTARGET_SMSM,
         &dest);
  v2 = WDFIOTARGET_SMSM;
  if ( v4 < STATUS_SUCCESS )
    return ((int (__fastcall *)(int, WDFIOTARGET))WdfFunctions.WdfObjectDelete)(WdfDriverGlobals, WDFIOTARGET_SMSM);
WDFIOTARGET_SMSM_ALREADY_SET:
  v5.Type = WdfMemoryDescriptorTypeBuffer;
  v5.u.BufferType.Buffer = v10;
  v5.u.BufferType.Length = 12;
  v10[0] = 0;
  v10[1] = 0;
  v10[2] = 0x800000;
  return WdfFunctions.WdfIoTargetSendIoctlSynchronously(
           WdfDriverGlobals,
           v2,
           NULL,
           0x32000,
           &v5,
           NULL,
           NULL,
           (ULONG *)v8);
}


// Function: EvtInterruptIsr
BOOLEAN __fastcall sub_4053EC(WDFINTERRUPT a1, ULONG a2)
{
  WdfFunctions.WdfInterruptQueueDpcForIsr(WdfDriverGlobals, a1);
  return 1;
}


// Function: EvtInterruptDpc
void __fastcall sub_405418(WDFINTERRUPT a1, WDFOBJECT a2)
{
  SMD_INTERRUPT_CONTEXT *v1; // r4
  unsigned __int64 v3; // r0
  int v4; // r5
  KIRQL v5; // r0
  int v6; // r3
  int v7; // r4

  v1 = (SMD_INTERRUPT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                  WdfDriverGlobals,
                                  a1,
                                  WDF_SMD_INTERRUPT_CONTEXT_TYPE_INFO.UniqueType);
  if ( *(_DWORD *)&v1->field_4 == 4 )
  {
    ++dword_41595C;
    if ( (*((_DWORD *)off_40F178 + 8) & 8) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v3) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v3) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_05(v3, 0xAu, &WPP_Traceguids_02);
    }
  }
  v4 = *(_DWORD *)&v1->field_0;
  v5 = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)(*(_DWORD *)&v1->field_0 + 28));
  v6 = *(_DWORD *)(v4 + 24);
  *(_BYTE *)(v4 + 32) = v5;
  if ( v6 )
  {
    do
    {
      v7 = *(_DWORD *)(v6 + 8);
      (*(void (__fastcall **)(int))(v6 + 48))(v6);
      v6 = v7;
    }
    while ( v7 );
  }
  KeReleaseSpinLock((KSPIN_LOCK *)(v4 + 28), *(_BYTE *)(v4 + 32));
}


// Function: smd_event_send
smd_interrupt_info_type *__fastcall smd_event_send(smd_stream_info_struct *info)
{
  smd_channel_type channel_type; // r1
  smd_interrupt_info_type *interrupt_info; // r0
  smem_host_type *v3; // r2
  smem_host_type to; // r1
  _DWORD *v6; // r2
  _DWORD *v7; // r3

  channel_type = info->channel_type;
  interrupt_info = &smdi_edges;
  v3 = &smdi_edges.to + 2 * channel_type;
  if ( *v3 && *(&smdi_edges.processor + 2 * channel_type) )
    goto LABEL_16;
  to = *v3;
  if ( *v3 == SMEM_APPS )
    to = *((_DWORD *)v3 + 1);
  if ( to == SMEM_TZ )
  {
LABEL_16:
    if ( (*((_DWORD *)off_40F178 + 8) & 4) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      return (smd_interrupt_info_type *)DoTraceMessage_07(*((_DWORD *)off_40F178 + 4), *((_DWORD *)off_40F178 + 5));
  }
  else
  {
    __dmb(0xFu);                                // ArmDataMemoryBarrier()
    interrupt_info = (smd_interrupt_info_type *)&smd_interrupt_table[5 * to];
    if ( interrupt_info && interrupt_info->irq_out )
    {
      if ( to == SMEM_WCN )
      {
        v6 = (_DWORD *)dword_415958;
        if ( dword_415958 )
        {
          __dsb(0xFu);
          *v6 = 0;
          v7 = (_DWORD *)dword_415958;
          __dsb(0xFu);
          *v7 = 2;
        }
      }
      *(_DWORD *)interrupt_info->irq_out = interrupt_info->irq_out_mask;
    }
  }
  return interrupt_info;
}


// Function: SmdAllocateAndInitializeSpinLock
// This function is a utility function for allocating and initializing a kernel spinlock. Spinlocks are used for synchronization in kernel-mode drivers to protect shared data structures from concurrent access.
KSPIN_LOCK *sub_405568()
{
  KSPIN_LOCK *result; // r0
  KSPIN_LOCK *v1; // r4

  result = (KSPIN_LOCK *)ExAllocatePoolWithTag(NonPagedPoolNx, 8u, 'qsda');
  v1 = result;
  if ( result )
  {
    KeInitializeSpinLock(result);
    return v1;
  }
  return result;
}


// Function: SmdCreateAndConfigureInterrupt
// This function is responsible for creating and configuring a WDF interrupt object for the SMD device. It sets up the ISR and DPC routines, and initializes a custom context for the interrupt, which includes storing smd_interrupt_info_type.
NTSTATUS __fastcall sub_4055AC(WDFDEVICE Device, smd_interrupt_info_type *a2)
{
  NTSTATUS result; // r0
  SMD_INTERRUPT_CONTEXT *v4; // r0
  void *v5; // [sp+8h] [bp-78h] BYREF
  _WDF_OBJECT_ATTRIBUTES v6; // [sp+10h] [bp-70h] BYREF
  _WDF_INTERRUPT_CONFIG v7; // [sp+30h] [bp-50h] BYREF
  int v8; // [sp+64h] [bp-1Ch]

  v7.SpinLock = 0;
  *(_DWORD *)&v7.FloatingSave = 0;
  memset(&v7.EvtInterruptEnable, 0, 28);
  v7.Size = 56;
  v7.ShareVector = WdfUseDefault;
  v7.EvtInterruptIsr = EvtInterruptIsr;
  v7.EvtInterruptDpc = EvtInterruptDpc;
  v8 = 2;
  v6.EvtCleanupCallback = 0;
  v6.EvtDestroyCallback = 0;
  v6.ParentObject = 0;
  v6.ContextSizeOverride = 0;
  v6.Size = 32;
  v6.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v6.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v6.ContextTypeInfo = (_WDF_OBJECT_CONTEXT_TYPE_INFO *)WDF_SMD_INTERRUPT_CONTEXT_TYPE_INFO.UniqueType;
  result = WdfFunctions.WdfInterruptCreate(WdfDriverGlobals, Device, &v7, &v6, &v5);
  if ( result >= STATUS_SUCCESS )
  {
    v4 = (SMD_INTERRUPT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                    WdfDriverGlobals,
                                    v5,
                                    WDF_SMD_INTERRUPT_CONTEXT_TYPE_INFO.UniqueType);
    *(_DWORD *)&v4->field_4 = a2;
    *(_DWORD *)&v4->field_0 = &dword_40FBE8;
    return STATUS_SUCCESS;
  }
  return result;
}


// Function: qcchipinfo8930_interface_changed
NTSTATUS __fastcall qcchipinfo8930_interface_changed(
        _DEVICE_INTERFACE_CHANGE_NOTIFICATION *NotificationStructure,
        WDFDEVICE Device)
{
  NTSTATUS result; // r0
  UNICODE_STRING *SymbolicLinkName; // r4
  NTSTATUS v6; // r4
  WDFIOTARGET v7; // r1
  int v8; // r0
  NTSTATUS v9; // r7
  _DWORD *v10; // r0
  _DWORD *v11; // r3
  WDFIOTARGET v12; // [sp+10h] [bp-80h] BYREF
  int v13; // [sp+14h] [bp-7Ch] BYREF
  unsigned int v14; // [sp+18h] [bp-78h] BYREF
  _WDF_MEMORY_DESCRIPTOR v15; // [sp+20h] [bp-70h] BYREF
  _WDF_IO_TARGET_OPEN_PARAMS dest; // [sp+30h] [bp-60h] BYREF

  v14 = 4096;
  v13 = 0;
  if ( !Device )
    return 3;
  if ( memcmp(&NotificationStructure->InterfaceClassGuid, &GUID_qcchipinfo8930_interface, 0x10u)
    || memcmp(&NotificationStructure->Event, &GUID_DEVICE_INTERFACE_ARRIVAL, 0x10u) )
  {
    return 3;
  }
  result = WdfFunctions.WdfIoTargetCreate(WdfDriverGlobals, Device, 0, &v12);
  if ( result >= STATUS_SUCCESS )
  {
    SymbolicLinkName = NotificationStructure->SymbolicLinkName;
    memset(&dest, 0, sizeof(dest));
    dest.Size = 72;
    dest.Type = WdfIoTargetOpenByName;
    dest.TargetDeviceName = *SymbolicLinkName;
    dest.DesiredAccess = 2031616;
    dest.CreateOptions = 64;
    dest.CreateDisposition = 1;
    v6 = ((int (__fastcall *)(int, WDFIOTARGET, _WDF_IO_TARGET_OPEN_PARAMS *))WdfFunctions.WdfIoTargetOpen)(
           WdfDriverGlobals,
           v12,
           &dest);
    v7 = v12;
    v8 = WdfDriverGlobals;
    if ( v6 < 0
      || (v15.Type = WdfMemoryDescriptorTypeBuffer,
          v15.u.BufferType.Buffer = &v13,
          v15.u.BufferType.Length = 4,
          v6 = WdfFunctions.WdfIoTargetSendIoctlSynchronously(WdfDriverGlobals, v12, 0, 0x8C1F2008, 0, &v15, 0, 0),
          v7 = v12,
          v8 = WdfDriverGlobals,
          v6 < 0) )
    {
      WdfFunctions.WdfObjectDelete(v8, v7);
      return v6;
    }
    else
    {
      v15.Type = WdfMemoryDescriptorTypeBuffer;
      v15.u.BufferType.Buffer = &v14;
      v15.u.BufferType.Length = 4;
      v9 = WdfFunctions.WdfIoTargetSendIoctlSynchronously(WdfDriverGlobals, v12, 0, 0x8C1F2004, 0, &v15, 0, 0);
      if ( v9 >= 0 && v13 == 87 && v14 < 0x20000 )
      {
        v10 = MmMapIoSpace(0x801284, 4u, MmNonCached);
        dword_415958 = (int)v10;
        __dsb(0xFu);
        *v10 = 0;
        v11 = (_DWORD *)dword_415958;
        __dsb(0xFu);
        *v11 = 2;
      }
      WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v12);
      return v9;
    }
  }
  return result;
}


// Function: smd_init
// See https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_main.c#L1375
NTSTATUS __fastcall smd_init(WDFDEVICE Device)
{
  NTSTATUS result; // r0
  int v3; // r0
  WDFDRIVER v4; // r0
  _DRIVER_OBJECT *wdmDriverObject; // r0
  _WDF_WORKITEM_CONFIG v6; // [sp+10h] [bp-40h] BYREF
  _WDF_OBJECT_ATTRIBUTES v7; // [sp+20h] [bp-30h] BYREF

  dword_40FBE8 = 0;
  dword_40FBF8 = 0;
  dword_40FBFC = 0;
  dword_40FC00 = 0;
  dword_40FC04 = 0;
  dword_40FC08 = 0;
  dword_40FBEC = (int)&dword_40FBEC;
  dword_40FBF0 = (int)&dword_40FBEC;
  dword_40FBF4 = 0;
  KeInitializeSpinLock(&dword_40FBF8);
  result = call_device_SMEM(Device);
  if ( result >= 0 )
  {
    sub_40745C();
    if ( smem_version_set )
      v3 = smem_version_set(0x6B, 0x20000, 0xFFFFFFFF);// SMEM_VERSION_SMD 0x6B
                                                // SMD_PROTOCOL_VERSION 0x00020000
                                                // SMEM_FULL_VERSION_MASK 0xFFFFFFFF
    else
      v3 = FALSE;
    if ( !v3 )
      fatal_error01("smd_init: SMD protocol version (%d) does not match", 0x20000);// SMD_PROTOCOL_VERSION 0x00020000
    KeInitializeSpinLock(&dword_40FC04);
    smd_interrupt_table = 7;
    dword_415A28 = 0;
    dword_415A2C = 0;
    dword_415A30 = 0;
    dword_415A34 = 7;
    dword_415A3C = 0;
    dword_415A40 = 0;
    dword_415A44 = 0;
    dword_415A48 = 7;
    dword_415A50 = 0;
    dword_415A54 = 0;
    dword_415A58 = 0;
    dword_415A5C = 7;
    dword_415A64 = 0;
    dword_415A68 = 0;
    dword_415A6C = 0;
    dword_415A70 = 7;
    dword_415A78 = 0;
    dword_415A7C = 0;
    dword_415A80 = 0;
    dword_415A84 = 7;
    dword_415A8C = 0;
    dword_415A90 = 0;
    dword_415A94 = 0;
    result = SmdLoadInterruptConfiguration(Device);
    if ( result >= 0 )
    {
      v7.EvtCleanupCallback = NULL;
      v7.EvtDestroyCallback = NULL;
      v7.ContextSizeOverride = NULL;
      v7.ContextTypeInfo = NULL;
      v7.Size = 32;
      v7.ExecutionLevel = WdfExecutionLevelInheritFromParent;
      v7.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
      *(_DWORD *)&v6.AutomaticSerialization = TRUE;
      v6.Size = 12;
      v6.EvtWorkItemFunc = (void (__fastcall *)(WDFWORKITEM *))SmdInitializeSmsmCommunication;
      v7.ParentObject = Device;
      result = WdfFunctions.WdfWorkItemCreate(WdfDriverGlobals, &v6, &v7, &dword_40FBE4);
      if ( result >= 0 )
      {
        v4 = WdfFunctions.WdfDeviceGetDriver(WdfDriverGlobals, Device);
        wdmDriverObject = WdfFunctions.WdfDriverWdmGetDriverObject(WdfDriverGlobals, v4);
        return IoRegisterPlugPlayNotification(
                 EventCategoryDeviceInterfaceChange,
                 1u,
                 &GUID_qcchipinfo8930_interface,
                 wdmDriverObject,
                 (DRIVER_NOTIFICATION_CALLBACK_ROUTINE *)qcchipinfo8930_interface_changed,
                 Device,
                 NotificationEntry_qcchipinfo8930_interface);
      }
    }
  }
  return result;
}


// Function: SmdProcessChannelCleanup
// This function appears to be a cleanup or shutdown routine that iterates through a list of SMD-related objects or contexts and performs specific actions based on a bitmask.
int __fastcall SmdProcessChannelCleanup(int a1)
{
  int *v2; // r4
  int v3; // r5
  int v4; // t1

  v2 = (int *)&unk_40E1C0;
  dword_40FC08 = KeAcquireSpinLockRaiseToDpc(&dword_40FC04);
  v3 = 6;
  do
  {
    v4 = *v2;
    v2 += 3;
    if ( (v4 & a1) != 0 )
    {
      if ( off_41594C )
        ((void (__fastcall *)(_DWORD))off_41594C)(*(v2 - 1));// sub_402A74 of qcsmem8930
      SmdProcessRemoteHostEvents((smem_host_type)*(v2 - 2));
    }
    --v3;
  }
  while ( v3 );
  KeReleaseSpinLock(&dword_40FC04, dword_40FC08);
  return 0;
}


// Function: SmdProcessRemoteHostEvents
// This function is a central handler for processing remote events or commands related to a specific host processor. It iterates through all SMD ports, and for those associated with the given host, it drives their state machines and signals events.
int __fastcall SmdProcessRemoteHostEvents(smem_host_type a1)
{
  unsigned int v2; // r2
  int result; // r0
  smd_info_struct **v4; // r3
  smd_info_struct *v5; // r7
  smd_channel_type channel_type; // r2
  ULONG port_id; // r9
  SMD_EVENT v10; // r4
  smd_info_struct *v11; // r6
  SMD_EVENT v12; // r8
  SMD_STREAM_STATE stream_state; // r5
  void (__fastcall *stream_close)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  smd_shared_stream_info_type *v15; // r3
  void (__fastcall *flush_cb)(void *); // r3
  void (__fastcall *stream_init)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r1
  smd_shared_stream_info_type *tx_shared_info_ptr; // r3
  smd_shared_stream_info_type *rx_shared_info_ptr; // r3
  smd_info_struct *v20; // r3
  void (__fastcall *stream_open)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  int *PortInfo; // r0
  int v24; // r2
  _DWORD *v26; // r1
  _DWORD *v27; // r4
  int v28; // r2
  smd_interrupt_info_type *v29; // r5
  smem_host_type to; // r2
  smd_interrupt_info_type *v32; // r1
  _DWORD *v33; // r3
  _DWORD *v34; // r3
  unsigned int v35; // [sp+0h] [bp-28h]
  smd_info_struct **v36; // [sp+4h] [bp-24h]

  v2 = 0;
  result = 1;
  v4 = (smd_info_struct **)smd_port_to_info;
  v35 = 0;
  while ( 1 )
  {
    v5 = *v4;
    v36 = v4 + 1;
    if ( *v4 && v5->protocol == SMD_STREAMING_BUFFER )
    {
      channel_type = v5->channel_type;
      if ( a1 == *((_DWORD *)&smdi_edges.to + 2 * channel_type) || a1 == *(&smdi_edges.processor + 2 * channel_type) )
      {
        port_id = v5->info.stream.port_id;
        v10 = SMD_EVENT_REMOTE_RESET;
        v11 = (smd_info_struct *)smd_port_to_info[port_id];
        while ( 2 )
        {
          v12 = v10;
          stream_state = v5->info.stream.tx_shared_info_ptr->stream_state;
          if ( v10 == SMD_EVENT_REMOTE_CLOSE )
          {
            stream_close = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))v5->info.stream.stream_close;
            if ( stream_close )
              stream_close(&v5->info);
          }
          switch ( stream_state )
          {
            case SMD_SS_CLOSED:
              v10 = smdi_stream_state_closed(v11, v10);
              goto LABEL_31;
            case SMD_SS_OPENING:
              switch ( v10 )
              {
                case SMD_EVENT_CLOSE:
                  goto LABEL_34;
                case SMD_EVENT_REMOTE_OPEN:
                  tx_shared_info_ptr = v11->info.stream.tx_shared_info_ptr;
                  if ( v11->info.stream.flush_pending )
                  {
                    v11->info.stream.flush_pending = 0;
                    tx_shared_info_ptr->stream_state = SMD_SS_FLUSHING;
                  }
                  else
                  {
                    tx_shared_info_ptr->stream_state = SMD_SS_OPENED;
                  }
                  break;
                case SMD_EVENT_FLUSH:
                  v11->info.stream.flush_pending = 1;
                  break;
                case SMD_EVENT_REMOTE_RESET:
                  goto LABEL_42;
                default:
                  goto LABEL_43;
              }
              goto LABEL_43;
            case SMD_SS_OPENED:
              switch ( v10 )
              {
                case SMD_EVENT_CLOSE:
LABEL_34:
                  smdi_stream_enter_closed_state(v11);
                  break;
                case SMD_EVENT_REMOTE_CLOSE:
                  v11->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_CLOSING;
                  break;
                case SMD_EVENT_FLUSH:
                  v11->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_FLUSHING;
                  v11->info.stream.tx_shared_info_ptr->if_sigs[7] = 0;
                  break;
                case SMD_EVENT_REMOTE_RESET:
LABEL_42:
                  v11->info.stream.rx_shared_info_ptr->stream_state = 0;
                  rx_shared_info_ptr = v11->info.stream.rx_shared_info_ptr;
                  *(_DWORD *)rx_shared_info_ptr->if_sigs = 0;
                  *(_DWORD *)&rx_shared_info_ptr->if_sigs[4] = 0;
                  v11->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
                  break;
                default:
                  goto LABEL_43;
              }
              goto LABEL_43;
            case SMD_SS_FLUSHING:
              v10 = smdi_stream_state_flushing(v11, v10);
              goto LABEL_31;
            case SMD_SS_CLOSING:
              switch ( v10 )
              {
                case SMD_EVENT_CLOSE:
                  goto LABEL_20;
                case SMD_EVENT_REMOTE_OPEN:
                case SMD_EVENT_REMOTE_REOPEN:
                  goto LABEL_30;
                case SMD_EVENT_FLUSH:
                  flush_cb = (void (__fastcall *)(void *))v11->info.stream.flush_cb;
                  if ( flush_cb )
                    flush_cb(v11->info.stream.flush_cb_data);
                  break;
                case SMD_EVENT_REMOTE_RESET:
                  v11->info.stream.rx_shared_info_ptr->stream_state = 0;// SMD_SS_CLOSED
                  v15 = v11->info.stream.rx_shared_info_ptr;
                  *(_DWORD *)v15->if_sigs = 0;
                  *(_DWORD *)&v15->if_sigs[4] = 0;
                  v11->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
                  break;
                default:
                  goto LABEL_31;
              }
              goto LABEL_31;
            case SMD_SS_RESET:
              switch ( v10 )
              {
                case SMD_EVENT_CLOSE:
LABEL_20:
                  smdi_stream_enter_closed_state(v11);
                  break;
                case SMD_EVENT_REMOTE_OPEN:
                case SMD_EVENT_REMOTE_REOPEN:
                  goto LABEL_30;
                case SMD_EVENT_REMOTE_CLOSE:
                  v11->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_CLOSING;
                  break;
                default:
                  goto LABEL_31;
              }
              goto LABEL_31;
            case SMD_SS_RESET_OPENING:
              if ( (unsigned int)v10 >= SMD_EVENT_REMOTE_OPEN
                && ((unsigned int)v10 <= SMD_EVENT_REMOTE_CLOSE || v10 == SMD_EVENT_REMOTE_REOPEN) )
              {
LABEL_30:
                stream_init = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))v11->info.stream.stream_init;
                v11->info.stream.max_queued_data = v11->info.stream.fifo_sz - 4;
                *(_DWORD *)&v11->info.stream.prev_dtr = 0;
                stream_init(&v11->info);
                v11->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
                v10 = SMD_EVENT_REMOTE_OPEN;
                *(_WORD *)&v11->info.stream.tx_shared_info_ptr->if_sigs[5] = 0;
                v11->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
              }
LABEL_31:
              if ( v12 != v10 )
                continue;
LABEL_43:
              v20 = (smd_info_struct *)smd_port_to_info[port_id];
              if ( v20 && v20->protocol == SMD_STREAMING_BUFFER )
              {
                v5->info.stream.tx_shared_info_ptr->if_sigs[6] = 1;
                smd_event_send(&v5->info.stream);
              }
              stream_open = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))v5->info.stream.stream_open;
              if ( stream_open )
                stream_open(&v5->info);
              v5->info.stream.prev_remote_state = 0;
              break;
            default:
              fatal_error02("Invalid stream state %d %d", (ULONG *)v11->port_id, (ULONG *)stream_state, 0);
          }
          break;
        }
LABEL_52:
        result = 1;
      }
    }
    else
    {
      PortInfo = SmdGetPortInfo(v2, (int)smd_port_to_info, v2, 0);
      if ( PortInfo )
      {
        v24 = PortInfo[2];
        if ( a1 == *((_DWORD *)&smdi_edges.to + 2 * v24) || a1 == *(&smdi_edges.processor + 2 * v24) )
        {
          if ( a1 == PortInfo[3] )
          {
            v26 = (_DWORD *)PortInfo[5];
            v27 = v26 + 5;
          }
          else
          {
            v27 = (_DWORD *)PortInfo[5];
            v26 = v27 + 5;
          }
          *v26 = 0;
          v26[1] = 0;
          v26[2] = 0;
          v28 = PortInfo[2];
          v29 = (smd_interrupt_info_type *)((char *)&smdi_edges + 8 * v28);
          if ( a1 == v29->to || a1 == *(&smdi_edges.processor + 2 * v28) )
          {
            to = v29->to;
            if ( a1 == v29->to )
              to = v29->processor;
          }
          else
          {
            to = SMEM_TZ;
          }
          *((_BYTE *)v26 + 10) = 1;
          __dmb(0xFu);
          v32 = (smd_interrupt_info_type *)&smd_interrupt_table[5 * to];
          if ( v32 && v32->irq_out )
          {
            if ( to == SMEM_WCN )
            {
              v33 = (_DWORD *)dword_415958;
              if ( dword_415958 )
              {
                __dsb(0xFu);
                *v33 = 0;
                v34 = (_DWORD *)dword_415958;
                __dsb(0xFu);
                *v34 = 2;
              }
            }
            *(_DWORD *)v32->irq_out = v32->irq_out_mask;
          }
          if ( PortInfo[2] == 11 )
          {
            *v27 = 0;
            v27[1] = 0;
            v27[2] = 0;
          }
          goto LABEL_52;
        }
      }
      result = 1;
    }
    v2 = v35 + 1;
    v35 = v2;
    if ( v2 >= 0x40 )
      return result;
    v4 = v36;
  }
}


// Function: SmdInitializeInterruptsFromConfig
// This function is responsible for initializing and configuring multiple SMD-related interrupts based on a provided configuration structure. It iterates through a list of interrupt configurations, populates the smd_interrupt_table, and then calls SmdCreateAndConfigureInterrupt for each interrupt.
NT_STATUS_VALUES __fastcall sub_405E14(WDFDEVICE Device, _DWORD *a2)
{
  _DWORD *v2; // r5
  unsigned int v3; // r1
  unsigned int v4; // r4
  _DWORD *v6; // r2
  unsigned int v7; // r6
  unsigned int v8; // r8
  smd_interrupt_info_type *v9; // r4
  int v10; // r7
  int v11; // r0
  smd_interrupt_info_type *v12; // r3

  v2 = a2;
  v3 = a2[2];
  v4 = 0;
  if ( v3 )
  {
    v6 = v2;
    while ( !*((_WORD *)v6 + 6) )
    {
      ++v4;
      v6 += 2;
      if ( v4 >= v3 )
        goto LABEL_5;
    }
  }
  else
  {
LABEL_5:
    v7 = v2[6];
    if ( v3 == 4 * (v7 + 1) )
    {
      v8 = 0;
      if ( !v7 )
        return STATUS_SUCCESS;
      while ( 1 )
      {
        v9 = (smd_interrupt_info_type *)v2[12];
        if ( (unsigned int)v9 >= SMEM_RPM )
          break;
        v10 = v2[16];
        v11 = sub_409DA4(v2[14]);
        if ( !v11 )
          break;
        smd_interrupt_table[5 * (_DWORD)v9] = (int)v9;
        v12 = (smd_interrupt_info_type *)&smd_interrupt_table[5 * (_DWORD)v9];
        v12->irq_out = v11;
        v12->irq_out_mask = v10;
        SmdCreateAndConfigureInterrupt(Device, v9);
        ++v8;
        v2 += 8;
        if ( v8 >= v7 )
          return STATUS_SUCCESS;
      }
    }
  }
  return STATUS_DEVICE_CONFIGURATION_ERROR;
}


// Function: SmdLoadInterruptConfiguration
// This function is responsible for retrieving interrupt configuration data from the device via an IOCTL and then using that data to initialize the SMD interrupts. It acts as a configuration loader for the SMD interrupt system.
NT_STATUS_VALUES __fastcall sub_405E98(WDFDEVICE Device)
{
  WDFIOTARGET v2; // r9
  NT_STATUS_VALUES result; // r0
  _DWORD *PoolWithTag; // r5
  int v5; // r4
  unsigned int v6; // r2
  int v7; // r4
  _WDF_MEMORY_DESCRIPTOR v8; // [sp+10h] [bp-60h] BYREF
  unsigned int v9; // [sp+1Ch] [bp-54h] BYREF
  _WDF_MEMORY_DESCRIPTOR v10; // [sp+20h] [bp-50h] BYREF
  _DWORD v11[3]; // [sp+30h] [bp-40h] BYREF
  size_t v12; // [sp+3Ch] [bp-34h]
  unsigned int v13; // [sp+40h] [bp-30h]
  int v14; // [sp+44h] [bp-2Ch]
  int v15; // [sp+48h] [bp-28h]

  strcpy((char *)v11, "AeiBINTR");
  v10.Type = WdfMemoryDescriptorTypeBuffer;
  v10.u.BufferType.Buffer = v11;
  v10.u.BufferType.Length = 8;
  BYTE1(v11[2]) = 0;
  HIWORD(v11[2]) = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v8.u.BufferType.Buffer = &v11[2];
  v8.u.BufferType.Length = 20;
  v8.Type = WdfMemoryDescriptorTypeBuffer;
  v2 = WdfFunctions.WdfDeviceGetIoTarget(WdfDriverGlobals, Device);
  result = WdfFunctions.WdfIoTargetSendIoctlSynchronously(WdfDriverGlobals, v2, NULL, 0x32C004, &v10, &v8, NULL, &v9);
  if ( result == STATUS_BUFFER_OVERFLOW )
  {
    PoolWithTag = ExAllocatePoolWithTag(NonPagedPoolNx, v12, 'qsdb');
    if ( !PoolWithTag )
      return STATUS_INSUFFICIENT_RESOURCES;
    v8.Type = WdfMemoryDescriptorTypeBuffer;
    v8.u = (union _WDF_MEMORY_DESCRIPTOR::$142A8D3BADC24534EE532293C58198B6)__PAIR64__(v12, (unsigned int)PoolWithTag);
    v5 = WdfFunctions.WdfIoTargetSendIoctlSynchronously(WdfDriverGlobals, v2, 0, 0x32C004, &v10, &v8, NULL, &v9);
    if ( v5 >= STATUS_SUCCESS )
    {
      if ( v9 >= 0x14 && *PoolWithTag == 'BoeA' )
      {
        v6 = PoolWithTag[2];
        if ( v6 )
        {
          if ( PoolWithTag[4] == 1 && v6 >= 4 )
          {
            v7 = SmdInitializeInterruptsFromConfig(Device, PoolWithTag);
            ExFreePool(PoolWithTag);
            return v7;
          }
        }
      }
      v5 = STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    ExFreePool(PoolWithTag);
    return v5;
  }
  else if ( result >= STATUS_SUCCESS )
  {
    if ( v9 >= 0x14 && v11[2] == 'BoeA' && v13 && v15 == 1 && v13 >= 4 )
      return SmdInitializeInterruptsFromConfig(Device, &v11[2]);
    else
      return STATUS_DEVICE_CONFIGURATION_ERROR;
  }
  return result;
}


// Function: fatal_error03
void __fastcall __noreturn fatal_error03(int a1, ULONG *a2)
{
  DbgPrintEx(0x4Du, 0, "Invalid index %x", a2);
  KeBugCheckEx(0x121u, a2, 0, 0, 0);
}


// Function: SmdProcessReceiveData
// This function is a helper function for reading data from an SMD stream's receive buffer, specifically handling packet-based data and fragmented reads. It calculates available data, manages bytes_remaining from previous operations, copies data, updates read indices, and signals events.
ULONG __fastcall sub_4060A0(smd_stream_info_struct *a1)
{
  smd_shared_stream_info_type *rx_shared_info_ptr; // r8
  ULONG fifo_sz; // r2
  unsigned int read_index; // r5
  ULONG write_index; // r6
  unsigned int v6; // r7
  ULONG bytes_remaining; // r3
  int v8; // r3
  PVOID reset_callback_fn; // r2
  int v10; // r0
  ULONG result; // r0
  ULONG v12; // r2

  rx_shared_info_ptr = a1->rx_shared_info_ptr;
  fifo_sz = a1->fifo_sz;
  read_index = rx_shared_info_ptr->read_index;
  if ( read_index >= fifo_sz )
    fatal_error03((int)a1, (ULONG *)rx_shared_info_ptr->read_index);
  write_index = rx_shared_info_ptr->write_index;
  if ( write_index >= fifo_sz )
    fatal_error03((int)a1, (ULONG *)rx_shared_info_ptr->write_index);
  if ( write_index != read_index )
  {
    if ( write_index >= read_index )
      v6 = write_index - read_index;
    else
      v6 = fifo_sz - read_index + write_index;
    bytes_remaining = a1->mode.memcpy.bytes_remaining;
    if ( bytes_remaining )
    {
      if ( bytes_remaining < v6 )
      {
        read_index += bytes_remaining;
        dword_415A00 = 1;
        if ( read_index >= fifo_sz )
          read_index -= fifo_sz;
        v6 -= bytes_remaining;
        a1->mode.memcpy.bytes_remaining = 0;
      }
      else
      {
        a1->mode.memcpy.bytes_remaining = bytes_remaining - v6;
        rx_shared_info_ptr->read_index = write_index;
        v6 = 0;
        v8 = a1->rx_shared_info_ptr->if_sigs[7];
        dword_415A00 = 1;
        read_index = write_index;
        if ( !v8 )
        {
          a1->tx_shared_info_ptr->if_sigs[5] = 1;
          smd_event_send(a1);
        }
      }
    }
    reset_callback_fn = a1->mode.memcpy.reset_callback_fn;
    if ( v6 > 20 - (int)reset_callback_fn )
      v6 = 20 - (_DWORD)reset_callback_fn;
    if ( v6 )
    {
      v10 = sub_409BB4(
              (int)&a1->mode.memcpy.reset_callback_data + (_DWORD)reset_callback_fn,
              (int)a1->rx_shared_fifo,
              v6,
              read_index,
              a1->fifo_sz);
      rx_shared_info_ptr->read_index = v10;
      read_index = v10;
      if ( !a1->rx_shared_info_ptr->if_sigs[7] )
      {
        a1->tx_shared_info_ptr->if_sigs[5] = 1;
        smd_event_send(a1);
      }
    }
    a1->mode.lite.packet_header_len += v6;
  }
  if ( a1->mode.lite.packet_header_len != 20 )
    return 0;
  result = a1->mode.lite.packet_header[0];
  v12 = write_index < read_index ? a1->fifo_sz - read_index + write_index : write_index - read_index;
  dword_415A00 = 1;
  if ( a1->mode.lite.continue_read + v12 < result && v12 != a1->fifo_sz - 4 )
    return 0;
  return result;
}


// Function: stream_init
smd_stream_info_struct *__fastcall stream_init(smd_stream_info_struct *result)
{
  result->tx_shared_info_ptr->write_index = 0;
  result->rx_shared_info_ptr->read_index = 0;
  return result;
}


// Function: stream_read
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_lite_api.c#L280
// 
void __fastcall stream_read(smd_stream_info_struct *a1)
{
  KSPIN_LOCK *tx_callback_data; // r4
  int v3; // r0
  ULONG v4; // r4
  smd_shared_stream_info_type *rx_shared_info_ptr; // r3
  ULONG fifo_sz; // r2
  ULONG *read_index; // r1
  ULONG *write_index; // r3
  void (__fastcall *rx_callback_data)(smd_stream_info_struct *, int, PVOID); // r6
  PVOID rx_flowctl_fn; // r7

  tx_callback_data = (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data;
  v3 = KeAcquireSpinLockRaiseToDpc(tx_callback_data);
  *((_BYTE *)tx_callback_data + 4) = v3;
  if ( a1->mode.memcpy.rx_callback_data )
  {
    if ( a1->mode.memcpy.tx_callback_fn )
    {
      rx_shared_info_ptr = a1->rx_shared_info_ptr;
      fifo_sz = a1->fifo_sz;
      read_index = (ULONG *)rx_shared_info_ptr->read_index;
      if ( (unsigned int)read_index >= fifo_sz )
        fatal_error03(v3, read_index);
      write_index = (ULONG *)rx_shared_info_ptr->write_index;
      if ( (unsigned int)write_index >= fifo_sz )
        fatal_error03(v3, write_index);
      v4 = (char *)write_index - (char *)read_index;
      if ( write_index < read_index )
        v4 += fifo_sz;
    }
    else
    {
      v4 = SmdProcessReceiveData(a1);
    }
    rx_callback_data = (void (__fastcall *)(smd_stream_info_struct *, int, PVOID))a1->mode.memcpy.rx_callback_data;
    rx_flowctl_fn = a1->mode.memcpy.rx_flowctl_fn;
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    if ( v4 )
      rx_callback_data(a1, 2, rx_flowctl_fn);
  }
  else
  {
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
  }
}


// Function: stream_write
void __fastcall stream_write(int a1)
{
  int v1; // r4
  void (__fastcall *v3)(int, int, int); // r6
  int v4; // r7

  v1 = *(_DWORD *)(a1 + 156);
  v3 = 0;
  v4 = 0;
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  if ( *(_DWORD *)(a1 + 168) && *(_DWORD *)(a1 + 160) )
  {
    v4 = *(_DWORD *)(a1 + 164);
    v3 = *(void (__fastcall **)(int, int, int))(a1 + 160);
  }
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 156), *(_BYTE *)(*(_DWORD *)(a1 + 156) + 4));
  if ( v3 )
    v3(a1, 3, v4);
}


// Function: nullsub_1
void nullsub_1()
{
  ;
}


// Function: stream_dtr
void __fastcall stream_dtr(smd_stream_info_struct *a1)
{
  KSPIN_LOCK *tx_callback_data; // r4
  void (__fastcall *rx_callback_data)(smd_stream_info_struct *, int, PVOID); // r4
  PVOID rx_flowctl_fn; // r6

  if ( a1->prev_dtr == 1 )
  {
    tx_callback_data = (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data;
    *((_BYTE *)tx_callback_data + 4) = KeAcquireSpinLockRaiseToDpc(tx_callback_data);
    rx_callback_data = (void (__fastcall *)(smd_stream_info_struct *, int, PVOID))a1->mode.memcpy.rx_callback_data;
    rx_flowctl_fn = a1->mode.memcpy.rx_flowctl_fn;
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    if ( rx_callback_data )
      rx_callback_data(a1, 1, rx_flowctl_fn);
  }
}


// Function: stream_reset
int stream_reset()
{
  return 0;
}


// Function: stream_close
int __fastcall stream_close(int result)
{
  int (__fastcall *v1)(int, int, _DWORD); // r3

  v1 = *(int (__fastcall **)(int, int, _DWORD))(result + 160);
  if ( v1 )
    return v1(result, 9, *(_DWORD *)(result + 164));
  return result;
}


// Function: stream_open
void __fastcall stream_open(int a1)
{
  int v1; // r4
  int v3; // r3
  int v4; // r4
  void (__fastcall *v5)(int, int, _DWORD); // r3

  v1 = *(_DWORD *)(a1 + 152);
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  v3 = *(_DWORD *)(a1 + 12);
  *(_BYTE *)(a1 + 64) = 0;
  *(_DWORD *)(v3 + 12) = 0;
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 152), *(_BYTE *)(*(_DWORD *)(a1 + 152) + 4));
  v4 = *(_DWORD *)(a1 + 156);
  *(_BYTE *)(v4 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v4);
  *(_DWORD *)(*(_DWORD *)(a1 + 8) + 16) = 0;
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 156), *(_BYTE *)(*(_DWORD *)(a1 + 156) + 4));
  v5 = *(void (__fastcall **)(int, int, _DWORD))(a1 + 160);
  if ( v5 )
    v5(a1, 9, *(_DWORD *)(a1 + 164));
}


// Function: SmdFreeContextResources
// This function is a cleanup or deallocation routine for a context structure. It frees memory associated with the context and then potentially calls a cleanup callback function.
void __fastcall sub_4063F8(int a1)
{
  void (__fastcall *v2)(int, int, _DWORD); // r3

  ExFreePool(*(PVOID *)(a1 + 152));
  ExFreePool(*(PVOID *)(a1 + 156));
  v2 = *(void (__fastcall **)(int, int, _DWORD))(a1 + 160);
  if ( v2 )
    v2(a1, 4, *(_DWORD *)(a1 + 164));
}


// Function: dtr_callback_ext
void __fastcall dtr_callback_ext(int a1)
{
  int v1; // r4
  void (__fastcall *v3)(int, int, int); // r4
  int v4; // r6

  v1 = *(_DWORD *)(a1 + 152);
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  v3 = *(void (__fastcall **)(int, int, int))(a1 + 160);
  v4 = *(_DWORD *)(a1 + 164);
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 152), *(_BYTE *)(*(_DWORD *)(a1 + 152) + 4));
  if ( v3 )
    v3(a1, 5, v4);
}


// Function: cts_callback_ext
void __fastcall cts_callback_ext(int a1)
{
  int v1; // r4
  void (__fastcall *v3)(int, int, int); // r4
  int v4; // r6

  v1 = *(_DWORD *)(a1 + 152);
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  v3 = *(void (__fastcall **)(int, int, int))(a1 + 160);
  v4 = *(_DWORD *)(a1 + 164);
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 152), *(_BYTE *)(*(_DWORD *)(a1 + 152) + 4));
  if ( v3 )
    v3(a1, 6, v4);
}


// Function: cd_callback_ext
void __fastcall cd_callback_ext(int a1)
{
  int v1; // r4
  void (__fastcall *v3)(int, int, int); // r4
  int v4; // r6

  v1 = *(_DWORD *)(a1 + 152);
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  v3 = *(void (__fastcall **)(int, int, int))(a1 + 160);
  v4 = *(_DWORD *)(a1 + 164);
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 152), *(_BYTE *)(*(_DWORD *)(a1 + 152) + 4));
  if ( v3 )
    v3(a1, 7, v4);
}


// Function: ri_callback_ext
void __fastcall ri_callback_ext(int a1)
{
  int v1; // r4
  void (__fastcall *v3)(int, int, int); // r4
  int v4; // r6

  v1 = *(_DWORD *)(a1 + 152);
  *(_BYTE *)(v1 + 4) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)v1);
  v3 = *(void (__fastcall **)(int, int, int))(a1 + 160);
  v4 = *(_DWORD *)(a1 + 164);
  KeReleaseSpinLock(*(KSPIN_LOCK **)(a1 + 152), *(_BYTE *)(*(_DWORD *)(a1 + 152) + 4));
  if ( v3 )
    v3(a1, 8, v4);
}


// Function: InterfaceFunction_00
// smdl_handle_type smdl_open
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_lite_api.c#L827
union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *__fastcall InterfaceFunction_00(
        char *name,
        smd_channel_type edge,
        smd_channel_protocol_type flags,
        ULONG fsize,
        void *notify,
        void *cb_data)
{
  __int32 v9; // r10
  smd_xfrflow_type v10; // r3
  ULONG *v11; // r9
  smd_info_struct *v12; // r8
  KSPIN_LOCK *v13; // r2
  void *tx_callback_data; // r0
  int v15; // r1
  int v16; // r2
  PVOID rx_callback_fn; // r0
  _DWORD v19[2]; // [sp+0h] [bp-30h] BYREF
  char v20; // [sp+8h] [bp-28h]

  if ( !name || !*name )
    return 0;
  if ( (unsigned int)edge >= SMD_APPS_RPM || fsize && ((fsize & 0x1F) != 0 || fsize < 0x400 || fsize > 0x20000) )
    return 0;
  v9 = flags & 4;
  if ( (flags & 4) != 0 )
    v10 = SMD_STREAMING_TYPE;
  else
    v10 = SMD_PKTXFR_TYPE;
  v11 = (ULONG *)smdi_alloc_channel_info(name, edge, flags, v10);
  v12 = smdi_alloc_info((ULONG)v11);
  smd_string_copy(v12->port_name, name, 0x14u);
  v12->protocol = SMD_STREAMING_BUFFER;
  v12->channel_type = edge;
  v12->info.stream.tx_flow_control_method = SMD_CTSRFR_FCTL;
  v12->info.stream.rx_flow_control_method = SMD_CTSRFR_FCTL;
  v12->info.stream.tx_fctl_enabled = 1;
  v12->info.stream.rx_fctl_enabled = 1;
  v12->info.stream.port_id = (ULONG)v11;
  v12->info.stream.channel_type = edge;
  v12->info.stream.dataxfr_mode = SMD_MEMCPY_MODE;
  if ( fsize )
    v12->info.stream.fifo_sz = fsize;
  else
    v12->info.stream.fifo_sz = 0x2000;
  dword_415A00 = 1;
  smdi_allocate_stream_channel(v11, &v12->info.stream.port_id, 1, (int)&dword_415A00);
  v12->info.stream.mode.memcpy.tx_callback_data = SmdAllocateAndInitializeSpinLock();
  v13 = SmdAllocateAndInitializeSpinLock();
  v12->info.stream.mode.memcpy.rx_callback_fn = v13;
  tx_callback_data = v12->info.stream.mode.memcpy.tx_callback_data;
  v12->info.stream.mode.memcpy.rx_callback_data = notify;
  v12->info.stream.mode.lite.notify_on_write = 0;
  v12->info.stream.mode.memcpy.rx_flowctl_fn = cb_data;
  if ( !tx_callback_data )
  {
LABEL_24:
    rx_callback_fn = v12->info.stream.mode.memcpy.rx_callback_fn;
    if ( rx_callback_fn )
      ExFreePool(rx_callback_fn);
    smdi_free_info(v12);
    return 0;
  }
  if ( !v13 )
  {
    ExFreePool(tx_callback_data);
    goto LABEL_24;
  }
  v12->info.stream.dtr_callback_ext_data = &v12->info;
  v12->info.stream.dtr_callback_ext_fn = dtr_callback_ext;
  v12->info.stream.cts_callback_ext_data = &v12->info;
  v12->info.stream.cd_callback_ext_data = &v12->info;
  v12->info.stream.cts_callback_ext_fn = cts_callback_ext;
  v12->info.stream.ri_callback_ext_data = &v12->info;
  v12->info.stream.cd_callback_ext_fn = cd_callback_ext;
  v12->info.stream.ri_callback_ext_fn = ri_callback_ext;
  v12->info.stream.tx_shared_info_ptr->if_sigs[0] = 1;
  v12->info.stream.tx_shared_info_ptr->if_sigs[2] = 1;
  v12->info.stream.tx_shared_info_ptr->if_sigs[1] = 1;
  if ( v9 )
    v12->info.stream.mode.memcpy.tx_callback_fn = (PVOID)1;
  else
    v12->info.stream.mode.memcpy.tx_callback_fn = 0;
  v12->context = (smd_context_type *)&dword_40FBE8;
  v19[0] = 7;                                   // SMD command
  v19[1] = v11;
  if ( strcmp(name, "LOOPBACK") || edge )
  {
    v20 = 0;
    smd_cmd((int)v19, v15, v16, 0);
    return &v12->info;
  }
  else
  {
    v20 = 1;
    smd_cmd((int)v19, v15, v16, 1);
    return &v12->info;
  }
}


// Function: InterfaceFunction_01
int __fastcall InterfaceFunction_01(SMD_PORT_CONTEXT *a1)
{
  SMD_PORT_CONTEXT *v2; // r3
  _DWORD v3[4]; // [sp+0h] [bp-18h] BYREF
  char v4; // [sp+10h] [bp-8h]

  if ( !a1 )
    return -1;
  v3[0] = 1;                                    // SMD command
  v2 = *(SMD_PORT_CONTEXT **)&a1->field_0;
  v3[3] = a1;
  v3[1] = v2;
  v3[2] = SmdFreeContextResources;
  v4 = 0;
  smd_cmd(v3);
  return 0;
}


// Function: InterfaceFunction_07
ULONG __fastcall InterfaceFunction_07(smd_stream_info_struct *a1)
{
  KSPIN_LOCK *tx_callback_data; // r4
  smd_shared_stream_info_type *tx_shared_info_ptr; // r5
  int v4; // r0
  ULONG v6; // r4
  smd_shared_stream_info_type *rx_shared_info_ptr; // r3
  ULONG fifo_sz; // r2
  ULONG *read_index; // r1
  ULONG *write_index; // r3

  tx_callback_data = (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data;
  tx_shared_info_ptr = a1->tx_shared_info_ptr;
  v4 = KeAcquireSpinLockRaiseToDpc(tx_callback_data);
  *((_BYTE *)tx_callback_data + 4) = v4;
  if ( tx_shared_info_ptr->stream_state == SMD_SS_OPENED )
  {
    if ( a1->mode.memcpy.tx_callback_fn )
    {
      rx_shared_info_ptr = a1->rx_shared_info_ptr;
      fifo_sz = a1->fifo_sz;
      read_index = (ULONG *)rx_shared_info_ptr->read_index;
      if ( (unsigned int)read_index >= fifo_sz )
        fatal_error03(v4, read_index);
      write_index = (ULONG *)rx_shared_info_ptr->write_index;
      if ( (unsigned int)write_index >= fifo_sz )
        fatal_error03(v4, write_index);
      v6 = (char *)write_index - (char *)read_index;
      if ( write_index < read_index )
        v6 += fifo_sz;
    }
    else
    {
      v6 = SmdProcessReceiveData(a1);
    }
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    return v6;
  }
  else
  {
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    return 0;
  }
}


// Function: InterfaceFunction_06
unsigned int __fastcall InterfaceFunction_06(SMD_PORT_CONTEXT *a1)
{
  KSPIN_LOCK *v3; // r4
  _DWORD *v4; // r6
  unsigned int v5; // r1
  unsigned int v6; // r0
  unsigned int v7; // r2
  unsigned int v8; // r4

  if ( !a1 )
    return -1;
  v3 = (KSPIN_LOCK *)a1->field_9c;
  v4 = *(_DWORD **)&a1->field_8;
  *((_BYTE *)v3 + 4) = KeAcquireSpinLockRaiseToDpc(v3);
  if ( *v4 == 2 && *(_BYTE *)(*(_DWORD *)&a1->field_c + 5) )
  {
    v5 = v4[4];
    v6 = *(_DWORD *)&a1[1].field_44;
    if ( v5 >= v6 )
      fatal_error03();
    v7 = v4[3];
    if ( v7 >= v6 )
      fatal_error03();
    v8 = v7 - v5 - 4;
    if ( v7 <= v5 )
      v8 += v6;
    if ( !a1->field_94 )
    {
      if ( v8 <= 0x14 )
        v8 = 0;
      else
        v8 -= 20;
    }
    KeReleaseSpinLock((KSPIN_LOCK *)a1->field_9c, *(_BYTE *)(a1->field_9c + 4));
    return v8;
  }
  else
  {
    KeReleaseSpinLock((KSPIN_LOCK *)a1->field_9c, *(_BYTE *)(a1->field_9c + 4));
    return 0;
  }
}


// Function: InterfaceFunction_02
unsigned int __fastcall InterfaceFunction_02(smd_stream_info_struct *a1, ULONG a2, int a3)
{
  ULONG v4; // r7
  KSPIN_LOCK *tx_callback_data; // r4
  smd_shared_stream_info_type *rx_shared_info_ptr; // r9
  smd_shared_stream_info_type *tx_shared_info_ptr; // r5
  unsigned int read_index; // r0
  ULONG fifo_sz; // r2
  ULONG *write_index; // r1
  unsigned int v14; // r4
  unsigned int v15; // r0
  ULONG v16; // r3

  v4 = 0;
  if ( a1 && a2 && a3 )
  {
    tx_callback_data = (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data;
    rx_shared_info_ptr = a1->rx_shared_info_ptr;
    tx_shared_info_ptr = a1->tx_shared_info_ptr;
    *((_BYTE *)tx_callback_data + 4) = KeAcquireSpinLockRaiseToDpc(tx_callback_data);
    if ( tx_shared_info_ptr->stream_state == 2
      && (a1->mode.memcpy.tx_callback_fn || (v4 = SmdProcessReceiveData(a1)) != 0) )
    {
      read_index = rx_shared_info_ptr->read_index;
      fifo_sz = a1->fifo_sz;
      if ( read_index >= fifo_sz )
        fatal_error03(read_index, (ULONG *)rx_shared_info_ptr->read_index);
      write_index = (ULONG *)rx_shared_info_ptr->write_index;
      if ( (unsigned int)write_index >= fifo_sz )
        fatal_error03(read_index, write_index);
      v14 = (unsigned int)write_index - read_index;
      if ( (unsigned int)write_index < read_index )
        v14 += fifo_sz;
      if ( !a1->mode.memcpy.tx_callback_fn )
      {
        if ( v4 > fifo_sz - 4 )
        {
          a1->mode.memcpy.bytes_remaining = v4 - fifo_sz + 4;
          dword_415A00 = 1;
          v4 = fifo_sz - 4;
        }
        if ( v14 < v4 )
        {
          v14 = 0;
        }
        else
        {
          v14 = v4;
          if ( v4 > a2 )
            v14 = a2;
          v15 = sub_409BB4(a3, (int)a1->rx_shared_fifo, v14, read_index, fifo_sz);
          if ( v4 > a2 )
          {
            v15 = v15 - a2 + v4;
            v16 = a1->fifo_sz;
            if ( v15 >= v16 )
              v15 -= v16;
          }
          rx_shared_info_ptr->read_index = v15;
          if ( !a1->rx_shared_info_ptr->if_sigs[7] )
          {
            a1->tx_shared_info_ptr->if_sigs[5] = 1;
            smd_event_send(a1);
          }
          a1->mode.lite.packet_header_len = 0;
        }
LABEL_30:
        KeReleaseSpinLock(
          (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data,
          *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
        dword_415A00 = 1;
        return v14;
      }
      if ( v14 )
      {
        if ( v14 >= a2 )
          v14 = a2;
        rx_shared_info_ptr->read_index = sub_409BB4(a3, (int)a1->rx_shared_fifo, v14, read_index, a1->fifo_sz);
        if ( !a1->rx_shared_info_ptr->if_sigs[7] )
        {
          a1->tx_shared_info_ptr->if_sigs[5] = 1;
          smd_event_send(a1);
        }
        goto LABEL_30;
      }
    }
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    return 0;
  }
  return -1;
}


// Function: InterfaceFunction_04
unsigned int __fastcall InterfaceFunction_04(smd_stream_info_struct *a1, unsigned int a2, unsigned int a3, char a4)
{
  unsigned int v7; // r6
  KSPIN_LOCK *rx_callback_fn; // r4
  smd_shared_stream_info_type *tx_shared_info_ptr; // r7
  PVOID v11; // r0
  unsigned int write_index; // r2
  ULONG fifo_sz; // r0
  ULONG *read_index; // r1
  unsigned int v15; // r4
  PVOID v16; // r0
  ULONG *v17; // r0
  int v18; // r0
  int v19; // r0
  ULONG *tx_shared_fifo; // r0
  int v21; // r0
  int v22; // r0
  ULONG v23; // [sp+0h] [bp-40h]
  ULONG v24; // [sp+0h] [bp-40h]
  _DWORD v25[6]; // [sp+8h] [bp-38h] BYREF

  v7 = a2;
  if ( !a1 || !a3 )
    return -1;
  if ( !a2 )
    return 0;
  rx_callback_fn = (KSPIN_LOCK *)a1->mode.memcpy.rx_callback_fn;
  tx_shared_info_ptr = a1->tx_shared_info_ptr;
  *((_BYTE *)rx_callback_fn + 4) = KeAcquireSpinLockRaiseToDpc(rx_callback_fn);
  if ( tx_shared_info_ptr->stream_state != 2 || !a1->rx_shared_info_ptr->if_sigs[1] )
  {
    v11 = a1->mode.memcpy.rx_callback_fn;
    a1->mode.lite.notify_on_write = 1;
    KeReleaseSpinLock((KSPIN_LOCK *)v11, *((_BYTE *)v11 + 4));
    v7 = 0;
LABEL_24:
    dword_415A00 = 1;
    return v7;
  }
  tx_shared_info_ptr->if_sigs[7] = 0;
  __dmb(0xFu);
  write_index = tx_shared_info_ptr->write_index;
  fifo_sz = a1->fifo_sz;
  if ( write_index >= fifo_sz )
    fatal_error03(fifo_sz, (ULONG *)tx_shared_info_ptr->write_index);
  read_index = (ULONG *)tx_shared_info_ptr->read_index;
  if ( (unsigned int)read_index >= fifo_sz )
    fatal_error03(fifo_sz, read_index);
  v15 = (unsigned int)read_index - write_index - 4;
  if ( (unsigned int)read_index <= write_index )
    v15 += fifo_sz;
  if ( a1->mode.memcpy.tx_callback_fn )
  {
    v24 = a1->fifo_sz;
    tx_shared_fifo = a1->tx_shared_fifo;
    if ( v15 < v7 )
    {
      a1->mode.lite.notify_on_write = 1;
      v21 = sub_409C04((int)tx_shared_fifo, a3, v15, write_index, v24);
      __dmb(0xFu);
      tx_shared_info_ptr->write_index = v21;
      v7 = v15;
      goto LABEL_22;
    }
    v22 = sub_409C04((int)tx_shared_fifo, a3, v7, write_index, v24);
    __dmb(0xFu);
    tx_shared_info_ptr->write_index = v22;
    a1->mode.lite.notify_on_write = 0;
LABEL_21:
    tx_shared_info_ptr->if_sigs[7] = 1;
LABEL_22:
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.rx_callback_fn, *((_BYTE *)a1->mode.memcpy.rx_callback_fn + 4));
    if ( (a4 & 1) == 0 )
    {
      a1->tx_shared_info_ptr->if_sigs[4] = 1;
      smd_event_send(a1);
    }
    goto LABEL_24;
  }
  if ( v15 >= v7 + 20 )
  {
    v23 = a1->fifo_sz;
    v17 = a1->tx_shared_fifo;
    memset(&v25[1], 0, 16);
    v25[0] = v7;
    v18 = sub_409C04((int)v17, (unsigned int)v25, 20, write_index, v23);
    v19 = sub_409C04((int)a1->tx_shared_fifo, a3, v7, v18, a1->fifo_sz);
    __dmb(0xFu);
    tx_shared_info_ptr->write_index = v19;
    a1->mode.lite.notify_on_write = 0;
    goto LABEL_21;
  }
  v16 = a1->mode.memcpy.rx_callback_fn;
  a1->mode.lite.notify_on_write = 1;
  KeReleaseSpinLock((KSPIN_LOCK *)v16, *((_BYTE *)v16 + 4));
  if ( v7 + 20 <= a1->fifo_sz - 4 )
    return 0;
  return -1;
}


// Function: SmdInitializeStreamAndStateMachine
// This function is a specialized SMD stream state machine that also initializes the stream's function pointers for various operations (read, write, init, close, etc.). It essentially sets up the operational callbacks for an SMD stream and then manages its state transitions based on incoming events.
int __fastcall sub_406BC0(int port_id)
{
  SMD_EVENT v1; // r5
  smd_info_struct *v2; // r7
  ULONG v3; // r10
  smd_info_struct *v4; // r4
  int v5; // r2
  SMD_STREAM_STATE v6; // r6
  SMD_EVENT v7; // r8
  void (__fastcall *v8)(int, _DWORD, int); // r3
  ULONG v9; // r3
  void (__fastcall *v10)(int); // r3
  smd_shared_stream_info_type *v11; // r3
  void (__fastcall *v12)(void *, _DWORD, int); // r3
  ULONG v13; // r3
  void (__fastcall *v14)(int); // r3
  ULONG v15; // r3
  void (__fastcall *v16)(int); // r3
  smd_shared_stream_info_type *v17; // r3
  smd_shared_stream_info_type *v18; // r3
  int v19; // r3

  v1 = SMD_EVENT_OPEN;
  v2 = (smd_info_struct *)smd_port_to_info[port_id];
  v2->info.stream.stream_init = stream_init;
  v3 = v2->info.stream.port_id;
  v2->info.stream.stream_read = stream_read;
  v2->info.stream.stream_write = stream_write;
  v2->info.stream.stream_flush_tx = nullsub_1;
  v2->info.stream.stream_dtr = stream_dtr;
  v2->info.stream.stream_drop = nullsub_1;
  v2->info.stream.stream_reset = stream_reset;
  v2->info.stream.stream_tx_abort = stream_reset;
  v2->info.stream.stream_close = stream_close;
  v2->info.stream.stream_open = stream_open;
  v4 = (smd_info_struct *)smd_port_to_info[v3];
  while ( 2 )
  {
    v5 = SMD_SS_CLOSING;
    v6 = v2->info.stream.tx_shared_info_ptr->stream_state;
    v7 = v1;
    if ( v1 == SMD_EVENT_REMOTE_CLOSE )
    {
      v8 = (void (__fastcall *)(int, _DWORD, int))v2->info.stream.stream_close;
      if ( v8 )
      {
        v8((int)&v2->info, 0, SMD_SS_CLOSING);
        v5 = SMD_SS_CLOSING;
      }
    }
    switch ( v6 )
    {
      case SMD_SS_CLOSED:
        v1 = smdi_stream_state_closed(v4, v1);
        goto LABEL_22;
      case SMD_SS_OPENING:
        switch ( v1 )
        {
          case SMD_EVENT_CLOSE:
            goto LABEL_25;
          case SMD_EVENT_REMOTE_OPEN:
            v17 = v4->info.stream.tx_shared_info_ptr;
            if ( v4->info.stream.flush_pending )
            {
              v4->info.stream.flush_pending = 0;
              v17->stream_state = SMD_SS_FLUSHING;
            }
            else
            {
              v17->stream_state = SMD_SS_OPENED;
            }
            break;
          case SMD_EVENT_FLUSH:
            v4->info.stream.flush_pending = 1;
            break;
          case SMD_EVENT_REMOTE_RESET:
            goto LABEL_33;
          default:
            goto LABEL_34;
        }
        goto LABEL_34;
      case SMD_SS_OPENED:
        switch ( v1 )
        {
          case SMD_EVENT_CLOSE:
LABEL_25:
            smdi_stream_enter_closed_state(v4);
            break;
          case SMD_EVENT_REMOTE_CLOSE:
            v4->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_CLOSING;
            break;
          case SMD_EVENT_FLUSH:
            v4->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_FLUSHING;
            v4->info.stream.tx_shared_info_ptr->if_sigs[7] = 0;
            break;
          case SMD_EVENT_REMOTE_RESET:
LABEL_33:
            v4->info.stream.rx_shared_info_ptr->stream_state = 0;// SMD_SS_CLOSED
            v18 = v4->info.stream.rx_shared_info_ptr;
            *(_DWORD *)v18->if_sigs = 0;
            *(_DWORD *)&v18->if_sigs[4] = 0;
            v4->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
            break;
          default:
            goto LABEL_34;
        }
        goto LABEL_34;
      case SMD_SS_FLUSHING:
        v1 = smdi_stream_state_flushing(v4, v1);
        goto LABEL_22;
      case SMD_SS_CLOSING:
        switch ( v1 )
        {
          case SMD_EVENT_CLOSE:
            goto LABEL_9;
          case SMD_EVENT_REMOTE_OPEN:
          case SMD_EVENT_REMOTE_REOPEN:
            v9 = v4->info.stream.fifo_sz;
            v4->info.stream.prev_dtr = 0;
            v4->info.stream.max_queued_data = v9 - 4;
            v10 = (void (__fastcall *)(int))v4->info.stream.stream_init;
            v4->info.stream.prev_cd = 0;
            v4->info.stream.prev_rts = 0;
            v4->info.stream.prev_ri = 0;
            v10((int)&v4->info);
            v1 = SMD_EVENT_REMOTE_OPEN;
            v4->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
            v4->info.stream.tx_shared_info_ptr->if_sigs[5] = 0;
            v4->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
            v4->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
            break;
          case SMD_EVENT_FLUSH:
            v12 = (void (__fastcall *)(void *, _DWORD, int))v4->info.stream.flush_cb;
            if ( v12 )
              v12(v4->info.stream.flush_cb_data, 0, SMD_SS_CLOSING);
            break;
          case SMD_EVENT_REMOTE_RESET:
            v4->info.stream.rx_shared_info_ptr->stream_state = 0;// SMD_SS_CLOSED
            v11 = v4->info.stream.rx_shared_info_ptr;
            *(_DWORD *)v11->if_sigs = 0;
            *(_DWORD *)&v11->if_sigs[4] = 0;
            v4->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
            break;
          default:
            goto LABEL_22;
        }
        goto LABEL_22;
      case SMD_SS_RESET:
        switch ( v1 )
        {
          case SMD_EVENT_CLOSE:
LABEL_9:
            smdi_stream_enter_closed_state(v4);
            break;
          case SMD_EVENT_REMOTE_OPEN:
          case SMD_EVENT_REMOTE_REOPEN:
            v13 = v4->info.stream.fifo_sz;
            v4->info.stream.prev_dtr = 0;
            v4->info.stream.max_queued_data = v13 - 4;
            v14 = (void (__fastcall *)(int))v4->info.stream.stream_init;
            v4->info.stream.prev_cd = 0;
            v4->info.stream.prev_rts = 0;
            v4->info.stream.prev_ri = 0;
            v14((int)&v4->info);
            v4->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
            v4->info.stream.tx_shared_info_ptr->if_sigs[5] = 0;
            v4->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
            v5 = 1;                             // SMD_SS_OPENING
            v1 = SMD_EVENT_REMOTE_OPEN;
            goto LABEL_17;
          case SMD_EVENT_REMOTE_CLOSE:
LABEL_17:
            v4->info.stream.tx_shared_info_ptr->stream_state = v5;
            break;
          default:
            goto LABEL_22;
        }
        goto LABEL_22;
      case SMD_SS_RESET_OPENING:
        if ( (unsigned int)v1 >= SMD_EVENT_REMOTE_OPEN
          && ((unsigned int)v1 <= SMD_EVENT_REMOTE_CLOSE || v1 == SMD_EVENT_REMOTE_REOPEN) )
        {
          v15 = v4->info.stream.fifo_sz;
          v4->info.stream.prev_dtr = 0;
          v4->info.stream.max_queued_data = v15 - 4;
          v16 = (void (__fastcall *)(int))v4->info.stream.stream_init;
          v4->info.stream.prev_cd = 0;
          v4->info.stream.prev_rts = 0;
          v4->info.stream.prev_ri = 0;
          v16((int)&v4->info);
          v4->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
          v1 = SMD_EVENT_REMOTE_OPEN;
          v4->info.stream.tx_shared_info_ptr->if_sigs[5] = 0;
          v4->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
          v4->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
        }
LABEL_22:
        if ( v7 != v1 )
          continue;
LABEL_34:
        v19 = smd_port_to_info[v3];
        if ( v19 && !*(_DWORD *)(v19 + 16) )
        {
          v2->info.stream.tx_shared_info_ptr->if_sigs[6] = 1;
          smd_event_send(&v2->info.stream);
        }
        return 6;
      default:
        fatal_error02("Invalid stream state %d %d", (ULONG *)v4->port_id, (ULONG *)v6, 0);
    }
  }
}


// Function: InterfaceFunction_03
unsigned int __fastcall InterfaceFunction_03(smd_stream_info_struct *a1, _DWORD *a2, char a3)
{
  unsigned int v4; // r8
  _DWORD *v6; // r7
  KSPIN_LOCK *tx_callback_data; // r4
  smd_shared_stream_info_type *rx_shared_info_ptr; // r9
  smd_shared_stream_info_type *tx_shared_info_ptr; // r5
  int v10; // r0
  unsigned int read_index; // lr
  ULONG fifo_sz; // r3
  ULONG *write_index; // r1
  unsigned int v15; // r9
  ULONG max_queued_data; // r2
  ULONG continue_read; // r2
  unsigned int v18; // r4
  unsigned int v19; // r5
  int v20; // r10
  ULONG v21; // r3
  int v22; // r0
  int v23; // r4
  ULONG *rx_shared_fifo; // r1
  int v25; // r0
  ULONG v26; // r3
  ULONG v27; // r2
  ULONG bytes_remaining; // r1
  ULONG v29; // r3
  ULONG v30; // [sp+0h] [bp-38h]
  unsigned int v31; // [sp+8h] [bp-30h]
  char *v32; // [sp+Ch] [bp-2Ch]
  smd_shared_stream_info_type *v34; // [sp+14h] [bp-24h]

  v4 = 0;
  v31 = 0;
  v6 = a2;
  if ( !a1 || !a2 )
    return -1;
  tx_callback_data = (KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data;
  rx_shared_info_ptr = a1->rx_shared_info_ptr;
  tx_shared_info_ptr = a1->tx_shared_info_ptr;
  v34 = rx_shared_info_ptr;
  v10 = KeAcquireSpinLockRaiseToDpc(tx_callback_data);
  *((_BYTE *)tx_callback_data + 4) = v10;
  if ( tx_shared_info_ptr->stream_state != 2 )
  {
LABEL_4:
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    return 0;
  }
  if ( a1->mode.lite.continue_read && (a3 & 2) == 0 )
  {
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
    dword_415A00 = 1;
    return -1;
  }
  if ( !a1->mode.memcpy.tx_callback_fn )
  {
    v10 = SmdProcessReceiveData(a1);
    v4 = v10;
    v31 = v10;
    if ( !v10 )
      goto LABEL_4;
  }
  read_index = rx_shared_info_ptr->read_index;
  fifo_sz = a1->fifo_sz;
  if ( read_index >= fifo_sz )
    fatal_error03(v10, (ULONG *)rx_shared_info_ptr->read_index);
  write_index = (ULONG *)rx_shared_info_ptr->write_index;
  if ( (unsigned int)write_index >= fifo_sz )
    fatal_error03(v10, write_index);
  v15 = (unsigned int)write_index - read_index;
  v32 = (char *)write_index - read_index;
  if ( read_index > (unsigned int)write_index )
  {
    v15 += fifo_sz;
    v32 = (char *)v15;
  }
  if ( a1->mode.memcpy.tx_callback_fn == (PVOID)1 )
  {
    v4 = v15;
    v31 = v15;
  }
  max_queued_data = a1->max_queued_data;
  if ( v4 > max_queued_data && (a3 & 2) == 0 )
  {
    a1->mode.memcpy.bytes_remaining = v4 - max_queued_data;
    dword_415A00 = 1;
    v4 = max_queued_data;
    v31 = max_queued_data;
  }
  continue_read = a1->mode.lite.continue_read;
  if ( !v15 )
    goto LABEL_4;
  if ( v15 < v4 && (a3 & 2) == 0 )
  {
    v18 = 0;
    goto LABEL_47;
  }
  v19 = v4 - continue_read;
  if ( v15 <= v4 - continue_read )
    v19 = v15;
  v20 = 0;
  while ( 1 )
  {
    v21 = v6[1];
    if ( !v21 )
      goto LABEL_35;
    v22 = v6[2];
    if ( !v22 )
      goto LABEL_35;
    if ( !continue_read || continue_read < v21 )
      break;
    continue_read -= v21;
LABEL_35:
    v6 = (_DWORD *)*v6;
    if ( !v6 )
      goto LABEL_36;
  }
  v23 = v21 - continue_read;
  if ( v21 - continue_read > v19 )
    v23 = v19;
  rx_shared_fifo = a1->rx_shared_fifo;
  v30 = a1->fifo_sz;
  dword_415A00 = 1;
  v25 = sub_409BB4(v22 + continue_read, (int)rx_shared_fifo, v23, read_index, v30);
  continue_read = 0;
  read_index = v25;
  v19 -= v23;
  v20 += v23;
  if ( v19 )
    goto LABEL_35;
LABEL_36:
  if ( (a3 & 2) != 0 && (v26 = a1->mode.lite.continue_read + v20, v26 < v31) && v6 )
  {
    v18 = 0x80000000;
  }
  else
  {
    v27 = a1->mode.lite.continue_read;
    bytes_remaining = a1->mode.memcpy.bytes_remaining;
    v18 = v27 + v20;
    if ( bytes_remaining + v31 > v27 + v20 )
    {
      read_index += (unsigned int)&v32[-v20];
      v29 = a1->fifo_sz;
      if ( read_index >= v29 )
        read_index -= v29;
      a1->mode.memcpy.bytes_remaining = bytes_remaining - v27 - (_DWORD)v32 + v31;
    }
    v26 = 0;
    a1->mode.lite.packet_header_len = 0;
  }
  a1->mode.lite.continue_read = v26;
  v34->read_index = read_index;
  if ( !a1->rx_shared_info_ptr->if_sigs[7] )
  {
    a1->tx_shared_info_ptr->if_sigs[5] = 1;
    smd_event_send(a1);
  }
LABEL_47:
  KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.tx_callback_data, *((_BYTE *)a1->mode.memcpy.tx_callback_data + 4));
  dword_415A00 = 1;
  return v18;
}


// Function: InterfaceFunction_05
unsigned int __fastcall InterfaceFunction_05(smd_stream_info_struct *a1, _DWORD *a2, char a3)
{
  _DWORD *v5; // r6
  ULONG v6; // r7
  _DWORD *v7; // r2
  int v8; // r3
  KSPIN_LOCK *rx_callback_fn; // r4
  smd_shared_stream_info_type *tx_shared_info_ptr; // r10
  int v11; // r0
  PVOID v13; // r0
  unsigned int write_index; // lr
  ULONG fifo_sz; // r2
  ULONG *read_index; // r1
  unsigned int v17; // r4
  ULONG v18; // r8
  PVOID v19; // r0
  ULONG *tx_shared_fifo; // r0
  ULONG continue_write; // r2
  unsigned int v22; // r9
  ULONG v23; // r3
  int v24; // r1
  PVOID v25; // r0
  int v26; // r8
  ULONG *v27; // r0
  int v28; // r0
  ULONG v29; // r3
  char v30; // r7
  ULONG v31; // [sp+0h] [bp-50h]
  _DWORD v33[6]; // [sp+18h] [bp-38h] BYREF

  v5 = a2;
  if ( !a1 || !a2 )
    return -1;
  v6 = 0;
  v7 = a2;
  do
  {
    v8 = v7[1];
    v7 = (_DWORD *)*v7;
    v6 += v8;
  }
  while ( v7 );
  if ( !v6 )
    return 0;
  rx_callback_fn = (KSPIN_LOCK *)a1->mode.memcpy.rx_callback_fn;
  dword_415A00 = 1;
  tx_shared_info_ptr = a1->tx_shared_info_ptr;
  v11 = KeAcquireSpinLockRaiseToDpc(rx_callback_fn);
  *((_BYTE *)rx_callback_fn + 4) = v11;
  if ( a1->mode.lite.continue_write && (a3 & 2) == 0 )
  {
    KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.rx_callback_fn, *((_BYTE *)a1->mode.memcpy.rx_callback_fn + 4));
    dword_415A00 = 1;
    return -1;
  }
  if ( tx_shared_info_ptr->stream_state != 2 || !a1->rx_shared_info_ptr->if_sigs[1] )
  {
    v13 = a1->mode.memcpy.rx_callback_fn;
    a1->mode.lite.notify_on_write = 1;
    KeReleaseSpinLock((KSPIN_LOCK *)v13, *((_BYTE *)v13 + 4));
    dword_415A00 = 1;
    return 0;
  }
  tx_shared_info_ptr->if_sigs[7] = 0;
  __dmb(0xFu);
  write_index = tx_shared_info_ptr->write_index;
  fifo_sz = a1->fifo_sz;
  if ( write_index >= fifo_sz )
    fatal_error03(v11, (ULONG *)tx_shared_info_ptr->write_index);
  read_index = (ULONG *)tx_shared_info_ptr->read_index;
  if ( (unsigned int)read_index >= fifo_sz )
    fatal_error03(v11, read_index);
  v17 = (unsigned int)read_index - write_index - 4;
  if ( (unsigned int)read_index <= write_index )
    v17 += fifo_sz;
  if ( a1->mode.memcpy.tx_callback_fn || a1->mode.lite.continue_write )
  {
    if ( !v17 )
    {
      v25 = a1->mode.memcpy.rx_callback_fn;
      a1->mode.lite.notify_on_write = 1;
      KeReleaseSpinLock((KSPIN_LOCK *)v25, *((_BYTE *)v25 + 4));
      return 0;
    }
  }
  else
  {
    if ( (a3 & 2) != 0 )
      v18 = 21;
    else
      v18 = v6 + 20;
    if ( v17 < v18 )
    {
      v19 = a1->mode.memcpy.rx_callback_fn;
      a1->mode.lite.notify_on_write = 1;
      KeReleaseSpinLock((KSPIN_LOCK *)v19, *((_BYTE *)v19 + 4));
      if ( v18 > a1->max_queued_data )
        return -1;
      return 0;
    }
    dword_415A00 = 1;
    tx_shared_fifo = a1->tx_shared_fifo;
    memset(&v33[1], 0, 16);
    v33[0] = v6;
    write_index = sub_409C04((int)tx_shared_fifo, (unsigned int)v33, 20, write_index, fifo_sz);
    v17 -= 20;
  }
  continue_write = a1->mode.lite.continue_write;
  v22 = v6 - continue_write;
  if ( v17 <= v6 - continue_write )
    v22 = v17;
  while ( 1 )
  {
    v23 = v5[1];
    if ( !v23 )
      goto LABEL_39;
    v24 = v5[2];
    if ( !v24 )
      goto LABEL_39;
    if ( !continue_write || continue_write < v23 )
      break;
    continue_write -= v23;
LABEL_39:
    v5 = (_DWORD *)*v5;
    if ( !v5 )
      goto LABEL_40;
  }
  v26 = v23 - continue_write;
  if ( v22 <= v23 - continue_write )
    v26 = v22;
  v27 = a1->tx_shared_fifo;
  v31 = a1->fifo_sz;
  dword_415A00 = 1;
  v28 = sub_409C04((int)v27, v24 + continue_write, v26, write_index, v31);
  continue_write = 0;
  write_index = v28;
  v22 -= v26;
  if ( v22 )
    goto LABEL_39;
LABEL_40:
  __dmb(0xFu);
  tx_shared_info_ptr->write_index = write_index;
  v29 = a1->mode.lite.continue_write + v17;
  if ( v29 >= v6 )
  {
    a1->mode.lite.notify_on_write = 0;
    a1->mode.lite.continue_write = 0;
    v17 = v6;
    v30 = a3;
    tx_shared_info_ptr->if_sigs[7] = 1;
  }
  else
  {
    v30 = a3;
    a1->mode.lite.notify_on_write = 1;
    if ( (a3 & 2) != 0 )
    {
      a1->mode.lite.continue_write = v29;
      v17 = 0x80000000;
    }
  }
  KeReleaseSpinLock((KSPIN_LOCK *)a1->mode.memcpy.rx_callback_fn, *((_BYTE *)a1->mode.memcpy.rx_callback_fn + 4));
  if ( (v30 & 1) == 0 )
  {
    a1->tx_shared_info_ptr->if_sigs[4] = 1;
    smd_event_send(a1);
  }
  dword_415A00 = 1;
  return v17;
}


// Function: InterfaceFunction_08
int __fastcall InterfaceFunction_08(smd_stream_info_struct *a1, int a2, unsigned int a3)
{
  smd_shared_stream_info_type *tx_shared_info_ptr; // r1
  int result; // r0
  smd_shared_stream_info_type *v5; // r1
  smd_shared_stream_info_type *v6; // r1
  smd_shared_stream_info_type *v7; // r1

  if ( !a1 || a3 > 1 )
    return -1;
  switch ( a2 )
  {
    case 0:
      tx_shared_info_ptr = a1->tx_shared_info_ptr;
      if ( tx_shared_info_ptr->if_sigs[0] == a3 )
        goto LABEL_12;
      tx_shared_info_ptr->if_sigs[0] = a3;
      a1->tx_shared_info_ptr->if_sigs[6] = 1;
      smd_event_send(a1);
      result = 0;
      break;
    case 1:
      v5 = a1->tx_shared_info_ptr;
      if ( v5->if_sigs[1] == a3 )
        goto LABEL_12;
      v5->if_sigs[1] = a3;
      a1->tx_shared_info_ptr->if_sigs[6] = 1;
      smd_event_send(a1);
      result = 0;
      break;
    case 2:
      v6 = a1->tx_shared_info_ptr;
      if ( v6->if_sigs[2] == a3 )
        goto LABEL_12;
      v6->if_sigs[2] = a3;
      a1->tx_shared_info_ptr->if_sigs[6] = 1;
      smd_event_send(a1);
      result = 0;
      break;
    case 3:
      v7 = a1->tx_shared_info_ptr;
      if ( v7->if_sigs[3] != a3 )
      {
        v7->if_sigs[3] = a3;
        a1->tx_shared_info_ptr->if_sigs[6] = 1;
        smd_event_send(a1);
      }
LABEL_12:
      result = 0;
      break;
    default:
      result = -1;
      break;
  }
  return result;
}


// Function: InterfaceFunction_09
int __fastcall InterfaceFunction_09(int a1, int a2)
{
  int result; // r0

  if ( !a1 )
    return -1;
  switch ( a2 )
  {
    case 0:
      result = *(unsigned __int8 *)(*(_DWORD *)(a1 + 12) + 4);
      break;
    case 1:
      result = *(unsigned __int8 *)(*(_DWORD *)(a1 + 12) + 5);
      break;
    case 2:
      result = *(unsigned __int8 *)(*(_DWORD *)(a1 + 12) + 6);
      break;
    case 3:
      result = *(unsigned __int8 *)(*(_DWORD *)(a1 + 12) + 7);
      break;
    default:
      result = -1;
      break;
  }
  return result;
}


// Function: fatal_error02
void __noreturn fatal_error02(CHAR *a1, ULONG *a2, ULONG *a3, ULONG *a4, ...)
{
  DbgPrintEx(0x4Du, 0, a1, a2, a3, a4);
  KeBugCheckEx(0x121u, a2, a3, a4, 0);
}


// Function: sub_40745C
void sub_40745C()
{
  _DWORD *v0; // r5
  int v1; // r0
  int v2; // r6
  _DWORD *v3; // r3
  _DWORD *v4; // r3
  int v5; // r2

  v0 = &unk_40FD20;
  memset(&unk_40FD20, 0, 0x5600u);
  memset(&smd_port_to_info, 0, 0x100u);
  if ( SMEM_ioctl42000_outputbuffer_size52 )
    v1 = SMEM_ioctl42000_outputbuffer_size52(13, 2048);// smem_alloc(SMEM_CHANNEL_ALLOC_TBL, 2048) of qcsmem8930
  else
    v1 = 0;
  dword_40FC0C = (int)&dword_40FC0C;
  dword_40FC10 = (int)&dword_40FC0C;
  dword_4159FC = v1;
  dword_40FC14 = 0;
  KeInitializeSpinLock(&dword_40FC18);
  v2 = 64;
  do
  {
    v0[5] = -1;
    *v0 = 0;
    v0[1] = 0;
    byte_40FC1C = KeAcquireSpinLockRaiseToDpc(&dword_40FC18);
    v3 = (_DWORD *)dword_40FC10;
    *v0 = &dword_40FC0C;
    v0[1] = v3;
    *v3 = v0;
    dword_40FC10 = (int)v0;
    ++dword_40FC14;
    KeReleaseSpinLock(&dword_40FC18, byte_40FC1C);
    v0 += 86;
    --v2;
  }
  while ( v2 );
  v4 = &dword_415320;
  v5 = 64;
  do
  {
    v4[1] = -1;
    v4 += 6;
    --v5;
  }
  while ( v5 );
}


// Function: smdi_alloc_info
smd_info_struct *__fastcall sub_40753C(ULONG port_id)
{
  smd_info_struct *v2; // r4
  KIRQL v3; // r0
  int v4; // r2
  smd_info_struct *result; // r0

  v2 = 0;
  v3 = KeAcquireSpinLockRaiseToDpc(&dword_40FC18);// start of q_get(q_type *q_ptr)
  byte_40FC1C = v3;
  v4 = dword_40FC0C;                            // smd_info_free_q ?
  if ( dword_40FC14 > 0 )
  {
    v2 = (smd_info_struct *)dword_40FC0C;
    dword_40FC0C = *(_DWORD *)dword_40FC0C;
    *(_DWORD *)(*(_DWORD *)v4 + 4) = &dword_40FC0C;
    --dword_40FC14;
    *(_DWORD *)v4 = 0;
    v3 = byte_40FC1C;
  }
  KeReleaseSpinLock(&dword_40FC18, v3);         // end of q_get(q_type *q_ptr)
  result = v2;
  if ( v2 )
  {
    memset(v2, 0, sizeof(smd_info_struct));
    v2->link.next_ptr = 0;
    v2->link.prev_ptr = 0;
    v2->port_id = port_id;
    smd_port_to_info[port_id] = v2;
    return v2;
  }
  return result;
}


// Function: smdi_free_info
void __fastcall smdi_free_info(smd_info_struct *info)
{
  ULONG port_id; // r6

  port_id = info->port_id;
  if ( smem_spin_lock )
    smem_spin_lock(3);                          // sub_402994 of qcsmem8930
  --*(_DWORD *)(dword_4159FC + 32 * port_id + 28);
  if ( smem_spin_unlock )                       // sub_402A10 of qcsmem8930
    ((void (__fastcall *)(int))smem_spin_unlock)(3);
  smd_port_to_info[info->port_id] = NULL;
  info->port_id = -1;                           // SMD_PORT_INVALID
  info->port_name[0] = NULL;
  info->context = NULL;
  byte_40FC1C = KeAcquireSpinLockRaiseToDpc(&dword_40FC18);
  info->link.next_ptr = (struct q_link_struct *)&dword_40FC0C;
  info->link.prev_ptr = (struct q_link_struct *)dword_40FC10;
  *(_DWORD *)dword_40FC10 = info;
  dword_40FC10 = (int)info;
  ++dword_40FC14;
  KeReleaseSpinLock(&dword_40FC18, byte_40FC1C);
}


// Function: smdi_stream_enter_closed_state
void __fastcall smdi_stream_enter_closed_state(smd_info_struct *info)
{
  smd_shared_stream_info_type *tx_shared_info_ptr; // r3
  smd_context_type *context; // r1
  smd_info_struct *open_list_cs; // r2
  smd_info_struct *next; // r3
  void (__fastcall *close_cb)(void *); // r5
  void *close_cb_data; // r6

  info->info.stream.tx_shared_info_ptr->stream_state = 0;// SMD_SS_CLOSED
  tx_shared_info_ptr = info->info.stream.tx_shared_info_ptr;
  *(_DWORD *)tx_shared_info_ptr->if_sigs = 0;   // FALSE
  *(_DWORD *)&tx_shared_info_ptr->if_sigs[4] = 0;// FALSE
  info->info.stream.tx_shared_info_ptr->if_sigs[6] = 1;// TRUE
  smd_event_send(&info->info.stream);
  if ( !info->info.stream.rx_shared_info_ptr->stream_state )
  {
    context = info->context;
    open_list_cs = (smd_info_struct *)context->os.open_list_cs;
    if ( open_list_cs == info )
    {
      context->os.open_list_cs = info->next;
    }
    else if ( open_list_cs )
    {
      while ( 1 )
      {
        next = open_list_cs->next;
        if ( next == info )
          break;
        open_list_cs = open_list_cs->next;
        if ( !next )
          goto LABEL_9;
      }
      open_list_cs->next = info->next;
    }
LABEL_9:
    close_cb = (void (__fastcall *)(void *))info->info.stream.close_cb;
    close_cb_data = info->info.stream.close_cb_data;
    smdi_free_info(info);
    if ( close_cb )
      close_cb(close_cb_data);
  }
}


// Function: smdi_stream_state_closed
SMD_EVENT __fastcall smdi_stream_state_closed(smd_info_struct *info, SMD_EVENT event)
{
  SMD_EVENT v2; // r5
  smd_context_type *v4; // r1
  smd_info_struct *open_list_cs; // r2
  smd_info_struct *next; // r3
  __int64 v7; // r6
  smd_context_type *context; // r2
  void (__fastcall *stream_init)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  ULONG stream_state; // r3

  v2 = event;
  if ( event == SMD_EVENT_OPEN )
  {
    context = info->context;
    info->next = (smd_info_struct *)context->os.open_list_cs;
    context->os.open_list_cs = info;
    if ( byte_415960 )
    {
      info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_RESET_OPENING;
      return SMD_EVENT_OPEN;
    }
    info->info.stream.max_queued_data = info->info.stream.fifo_sz - 4;
    stream_init = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))info->info.stream.stream_init;
    *(_DWORD *)&info->info.stream.prev_dtr = 0;
    stream_init(&info->info);
    info->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
    info->info.stream.tx_shared_info_ptr->if_sigs[5] = 0;
    info->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
    info->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
    stream_state = info->info.stream.rx_shared_info_ptr->stream_state;
    if ( stream_state && stream_state != SMD_SS_CLOSING && stream_state != SMD_SS_RESET )
      return SMD_EVENT_REMOTE_OPEN;
  }
  else if ( event == SMD_EVENT_REMOTE_CLOSE )
  {
    v4 = info->context;
    open_list_cs = (smd_info_struct *)v4->os.open_list_cs;
    if ( open_list_cs == info )
    {
      v4->os.open_list_cs = info->next;
    }
    else if ( open_list_cs )
    {
      while ( 1 )
      {
        next = open_list_cs->next;
        if ( next == info )
          break;
        open_list_cs = open_list_cs->next;
        if ( !next )
          goto LABEL_10;
      }
      open_list_cs->next = info->next;
    }
LABEL_10:
    v7 = *(_QWORD *)&info->info.stream.close_cb;
    smdi_free_info(info);
    if ( (_DWORD)v7 )
    {
      ((void (__fastcall *)(_DWORD))v7)(HIDWORD(v7));
      return SMD_EVENT_REMOTE_CLOSE;
    }
  }
  return v2;
}


// Function: smdi_stream_state_flushing
SMD_EVENT __fastcall smdi_stream_state_flushing(smd_info_struct *info, SMD_EVENT event)
{
  SMD_EVENT result; // r0
  void (__fastcall *v5)(void *); // r3
  void (__fastcall *flush_cb)(void *); // r3
  smd_shared_stream_info_type *rx_shared_info_ptr; // r3

  switch ( event )
  {
    case SMD_EVENT_CLOSE:
      info->info.stream.close_pending = 1;
      result = event;
      break;
    case SMD_EVENT_REMOTE_CLOSE:
      flush_cb = (void (__fastcall *)(void *))info->info.stream.flush_cb;
      if ( flush_cb )
        flush_cb(info->info.stream.flush_cb_data);
      if ( info->info.stream.close_pending )
        goto LABEL_6;
      info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_CLOSING;
      result = event;
      break;
    case SMD_EVENT_FLUSH_COMPLETE:
      v5 = (void (__fastcall *)(void *))info->info.stream.flush_cb;
      if ( v5 )
        v5(info->info.stream.flush_cb_data);
      if ( info->info.stream.close_pending )
      {
LABEL_6:
        info->info.stream.close_pending = 0;
        smdi_stream_enter_closed_state(info);
        result = event;
      }
      else
      {
        info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_OPENED;
        result = event;
      }
      break;
    case SMD_EVENT_REMOTE_RESET:
      info->info.stream.rx_shared_info_ptr->stream_state = 0;// SMD_SS_CLOSED
      rx_shared_info_ptr = info->info.stream.rx_shared_info_ptr;
      *(_DWORD *)rx_shared_info_ptr->if_sigs = 0;
      *(_DWORD *)&rx_shared_info_ptr->if_sigs[4] = 0;
      info->info.stream.tx_shared_info_ptr->stream_state = 1;// SMD_SS_OPENING
      goto LABEL_13;
    default:
LABEL_13:
      result = event;
      break;
  }
  return result;
}


// Function: smdi_stream_state_machine
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_internal.c#L1317
void __fastcall smdi_stream_state_machine(smd_stream_info_struct *sinfo, SMD_EVENT event)
{
  ULONG port_id; // r9
  smd_info_struct *info; // r4
  SMD_STREAM_STATE v6; // r2
  ULONG *stream_state; // r6
  SMD_EVENT prev_event; // r8
  void (__fastcall *stream_close)(smd_stream_info_struct *, _DWORD, SMD_STREAM_STATE); // r3
  ULONG fifo_sz; // r3
  void (__fastcall *stream_init)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  smd_shared_stream_info_type *v12; // r3
  void (__fastcall *flush_cb)(void *, _DWORD, SMD_STREAM_STATE); // r3
  ULONG v14; // r3
  void (__fastcall *v15)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  ULONG v16; // r3
  void (__fastcall *v17)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *); // r3
  smd_shared_stream_info_type *tx_shared_info_ptr; // r3
  smd_shared_stream_info_type *rx_shared_info_ptr; // r3
  smd_info_struct *v20; // r3

  port_id = sinfo->port_id;
  info = (smd_info_struct *)smd_port_to_info[sinfo->port_id];
  while ( 2 )
  {
    v6 = SMD_SS_CLOSING;
    stream_state = (ULONG *)sinfo->tx_shared_info_ptr->stream_state;
    prev_event = event;
    if ( event == SMD_EVENT_REMOTE_CLOSE )
    {
      stream_close = (void (__fastcall *)(smd_stream_info_struct *, _DWORD, SMD_STREAM_STATE))sinfo->stream_close;
      if ( stream_close )
      {
        stream_close(sinfo, FALSE, SMD_SS_CLOSING);
        v6 = SMD_SS_CLOSING;
      }
    }
    switch ( (unsigned int)stream_state )
    {
      case SMD_SS_CLOSED:
        event = smdi_stream_state_closed((int)info, event);
        goto LABEL_22;
      case SMD_SS_OPENING:
        switch ( event )
        {
          case SMD_EVENT_CLOSE:
            goto LABEL_25;
          case SMD_EVENT_REMOTE_OPEN:
            tx_shared_info_ptr = info->info.stream.tx_shared_info_ptr;
            if ( info->info.stream.flush_pending )
            {
              info->info.stream.flush_pending = FALSE;
              tx_shared_info_ptr->stream_state = 3;
            }
            else
            {
              tx_shared_info_ptr->stream_state = 2;
            }
            break;
          case SMD_EVENT_FLUSH:
            info->info.stream.flush_pending = SMD_SS_OPENING;
            break;
          case SMD_EVENT_REMOTE_RESET:
            goto LABEL_33;
          default:
            goto LABEL_34;
        }
        goto LABEL_34;
      case SMD_SS_OPENED:
        switch ( event )
        {
          case SMD_EVENT_CLOSE:
LABEL_25:
            smdi_stream_enter_closed_state((int)info);
            break;
          case SMD_EVENT_REMOTE_CLOSE:
            info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_CLOSING;
            break;
          case SMD_EVENT_FLUSH:
            info->info.stream.tx_shared_info_ptr->stream_state = 3;
            info->info.stream.tx_shared_info_ptr->if_sigs[7] = FALSE;
            break;
          case SMD_EVENT_REMOTE_RESET:
LABEL_33:
            info->info.stream.rx_shared_info_ptr->stream_state = FALSE;// SMD_SS_CLOSED
            rx_shared_info_ptr = info->info.stream.rx_shared_info_ptr;
            *(_DWORD *)rx_shared_info_ptr->if_sigs = 0;
            *(_DWORD *)&rx_shared_info_ptr->if_sigs[4] = 0;
            info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_OPENING;
            break;
          default:
            goto LABEL_34;
        }
        goto LABEL_34;
      case SMD_SS_FLUSHING:
        event = smdi_stream_state_flushing((int)info, event);
        goto LABEL_22;
      case SMD_SS_CLOSING:
        switch ( event )
        {
          case SMD_EVENT_CLOSE:
            goto LABEL_9;
          case SMD_EVENT_REMOTE_OPEN:
          case SMD_EVENT_REMOTE_REOPEN:
            fifo_sz = info->info.stream.fifo_sz;
            info->info.stream.prev_dtr = FALSE;
            info->info.stream.max_queued_data = fifo_sz - 4;
            stream_init = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))info->info.stream.stream_init;
            *(_WORD *)&info->info.stream.prev_cd = FALSE;
            info->info.stream.prev_ri = FALSE;
            stream_init(&info->info);
            event = SMD_EVENT_REMOTE_OPEN;
            *(_WORD *)&info->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
            info->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
            info->info.stream.tx_shared_info_ptr->stream_state = 1;
            break;
          case SMD_EVENT_FLUSH:
            flush_cb = (void (__fastcall *)(void *, _DWORD, SMD_STREAM_STATE))info->info.stream.flush_cb;
            if ( flush_cb )
              flush_cb(info->info.stream.flush_cb_data, FALSE, SMD_SS_CLOSING);
            break;
          case SMD_EVENT_REMOTE_RESET:
            info->info.stream.rx_shared_info_ptr->stream_state = FALSE;
            v12 = info->info.stream.rx_shared_info_ptr;
            *(_DWORD *)v12->if_sigs = 0;
            *(_DWORD *)&v12->if_sigs[4] = 0;
            info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_OPENING;
            break;
          default:
            goto LABEL_22;
        }
        goto LABEL_22;
      case SMD_SS_RESET:
        switch ( event )
        {
          case SMD_EVENT_CLOSE:
LABEL_9:
            smdi_stream_enter_closed_state((int)info);
            break;
          case SMD_EVENT_REMOTE_OPEN:
          case SMD_EVENT_REMOTE_REOPEN:
            v14 = info->info.stream.fifo_sz;
            info->info.stream.prev_dtr = FALSE;
            info->info.stream.max_queued_data = v14 - 4;
            v15 = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))info->info.stream.stream_init;
            *(_WORD *)&info->info.stream.prev_cd = FALSE;
            info->info.stream.prev_ri = FALSE;
            v15(&info->info);
            *(_WORD *)&info->info.stream.tx_shared_info_ptr->if_sigs[4] = 0;
            info->info.stream.tx_shared_info_ptr->if_sigs[6] = 0;
            v6 = SMD_SS_OPENING;
            event = SMD_EVENT_REMOTE_OPEN;
            goto LABEL_17;
          case SMD_EVENT_REMOTE_CLOSE:
LABEL_17:
            info->info.stream.tx_shared_info_ptr->stream_state = v6;
            break;
          default:
            goto LABEL_22;
        }
        goto LABEL_22;
      case SMD_SS_RESET_OPENING:
        if ( (unsigned int)event >= SMD_EVENT_REMOTE_OPEN
          && ((unsigned int)event <= SMD_EVENT_REMOTE_CLOSE || event == SMD_EVENT_REMOTE_REOPEN) )
        {
          v16 = info->info.stream.fifo_sz;
          info->info.stream.prev_dtr = FALSE;
          info->info.stream.max_queued_data = v16 - 4;
          v17 = (void (__fastcall *)(union smd_info_struct::$848CAD007328EF98E26EC012B56848F4 *))info->info.stream.stream_init;
          *(_WORD *)&info->info.stream.prev_cd = FALSE;
          info->info.stream.prev_ri = FALSE;
          v17(&info->info);
          info->info.stream.tx_shared_info_ptr->if_sigs[4] = FALSE;
          event = SMD_EVENT_REMOTE_OPEN;
          *(_WORD *)&info->info.stream.tx_shared_info_ptr->if_sigs[5] = FALSE;
          info->info.stream.tx_shared_info_ptr->stream_state = SMD_SS_OPENING;
        }
LABEL_22:
        if ( prev_event != event )
          continue;
LABEL_34:
        v20 = (smd_info_struct *)smd_port_to_info[port_id];
        if ( v20 && v20->protocol == SMD_STREAMING_BUFFER )
        {
          sinfo->tx_shared_info_ptr->if_sigs[6] = 1;
          smd_event_send((int)sinfo);
        }
        return;
      default:
        fatal_error02("Invalid stream state %d %d", (ULONG *)info->port_id, stream_state, 0);// info->port_id, stream_state
    }
  }
}


// Function: SmdGlobalStreamStateMachine
// This function is a comprehensive SMD stream management function, acting as a central dispatcher for events and state transitions across multiple SMD streams or channels. It handles various events, updates stream states, and invokes appropriate callbacks.
int __fastcall sub_407A64(int result)
{
  ULONG *v1; // r2
  ULONG *v2; // r3
  int v3; // r9
  unsigned int v4; // r5
  int v5; // r4
  int v6; // r2
  ULONG *v7; // r6
  unsigned int v8; // r7
  void (*v9)(void); // r3
  int v10; // r3
  void (__fastcall *v11)(_DWORD, int, int); // r3
  int v12; // r3
  void (__fastcall *v13)(int, int, int); // r3
  int *v14; // r3
  int v15; // r3
  int v16; // r3
  int v17; // r3
  int v18; // r9
  unsigned int v19; // r4
  int info; // r5
  int v21; // r2
  ULONG *v22; // r6
  unsigned int v23; // r7
  void (*v24)(void); // r3
  int v25; // r3
  void (__fastcall *v26)(_DWORD, int, int); // r3
  void (__fastcall *v27)(int); // r1
  int *v28; // r3
  int v29; // r3
  int v30; // r3
  int v31; // r3
  unsigned int v32; // r4
  ULONG *v33; // r6
  unsigned int v34; // r7
  void (*v35)(void); // r3
  int v36; // r3
  void (__fastcall *v37)(_DWORD, int, int); // r3
  void (__fastcall *v38)(int); // r1
  unsigned int v39; // r4
  ULONG *v40; // r6
  unsigned int v41; // r7
  void (*v42)(void); // r3
  int v43; // r3
  void (__fastcall *v44)(_DWORD, int, int); // r3
  void (__fastcall *v45)(int); // r1
  int v46; // r3
  unsigned int v47; // r4
  ULONG *v48; // r6
  unsigned int v49; // r7
  void (*v50)(void); // r3
  int v51; // r3
  void (__fastcall *v52)(_DWORD, int, int); // r3
  void (__fastcall *v53)(int); // r1
  unsigned int v54; // r4
  ULONG *v55; // r6
  unsigned int v56; // r7
  void (*v57)(void); // r3
  int v58; // r3
  void (__fastcall *v59)(_DWORD, int, int); // r3
  void (__fastcall *v60)(int); // r1
  unsigned int event; // r4
  ULONG *v62; // r6
  unsigned int v63; // r7
  void (*v64)(void); // r3
  int v65; // r3
  void (__fastcall *v66)(_DWORD, int, int); // r3
  void (__fastcall *v67)(int); // r1
  unsigned int v68; // r4
  ULONG *v69; // r6
  unsigned int v70; // r7
  void (*v71)(void); // r3
  int v72; // r3
  void (__fastcall *v73)(_DWORD, int, int); // r3
  void (__fastcall *v74)(int); // r1
  int v75; // r3
  unsigned int v76; // r4
  ULONG *v77; // r6
  unsigned int v78; // r7
  void (*v79)(void); // r3
  int v80; // r3
  void (__fastcall *v81)(_DWORD, int, int); // r3
  void (__fastcall *v82)(int); // r1
  unsigned int v83; // r4
  ULONG *v84; // r6
  unsigned int v85; // r7
  void (*v86)(void); // r3
  int v87; // r3
  void (__fastcall *v88)(_DWORD, int, int); // r3
  void (__fastcall *v89)(int); // r1
  unsigned int v90; // r4
  ULONG *v91; // r6
  unsigned int v92; // r7
  void (*v93)(void); // r3
  int v94; // r3
  void (__fastcall *v95)(_DWORD, int, int); // r3
  void (__fastcall *v96)(int); // r1
  int v97; // r9
  unsigned int v98; // r5
  int v99; // r4
  int v100; // r2
  ULONG *v101; // r6
  unsigned int v102; // r7
  void (*v103)(void); // r3
  int v104; // r3
  void (__fastcall *v105)(_DWORD, int, int); // r3
  int v106; // r3
  void (__fastcall *v107)(int, int, int); // r3
  int *v108; // r3
  int v109; // r3
  int v110; // r3
  int v112; // [sp+0h] [bp-28h]
  ULONG *v113; // [sp+4h] [bp-24h]

  v1 = *(ULONG **)(result + 80);
  v112 = result;
  v2 = **(ULONG ***)(result + 12);
  v113 = v2;
  if ( v1 == v2 )
    return result;
  if ( v2 && v2 != (ULONG *)4 )
  {
    if ( v2 == (ULONG *)5 )
    {
      v3 = *(_DWORD *)result;
      v4 = 7;
      v5 = smd_port_to_info[*(_DWORD *)result];
      v6 = 1;
      while ( 1 )
      {
        v7 = **(ULONG ***)(result + 8);
        v8 = v4;
        if ( v4 == 3 )
        {
          v9 = *(void (**)(void))(result + 124);
          if ( v9 )
          {
            v9();
            v6 = 1;
          }
        }
        switch ( (unsigned int)v7 )
        {
          case 0u:
            v4 = smdi_stream_state_closed(v5, v4);
            v6 = 1;
            goto LABEL_25;
          case 1u:
            switch ( v4 )
            {
              case 0u:
                goto LABEL_28;
              case 2u:
                v14 = *(int **)(v5 + 60);
                if ( *(_BYTE *)(v5 + 129) )
                {
                  *(_BYTE *)(v5 + 129) = 0;
                  v6 = 3;
                }
                else
                {
                  v6 = 2;
                }
                goto LABEL_37;
              case 4u:
                *(_BYTE *)(v5 + 129) = 1;
                break;
              case 7u:
                goto LABEL_36;
              default:
                goto LABEL_38;
            }
            goto LABEL_38;
          case 2u:
            switch ( v4 )
            {
              case 0u:
LABEL_28:
                smdi_stream_enter_closed_state(v5);
                break;
              case 3u:
                **(_DWORD **)(v5 + 60) = 4;
                break;
              case 4u:
                **(_DWORD **)(v5 + 60) = 3;
                *(_BYTE *)(*(_DWORD *)(v5 + 60) + 11) = 0;
                break;
              case 7u:
LABEL_36:
                **(_DWORD **)(v5 + 64) = 0;
                v15 = *(_DWORD *)(v5 + 64);
                *(_DWORD *)(v15 + 4) = 0;
                *(_DWORD *)(v15 + 8) = 0;
                v14 = *(int **)(v5 + 60);
LABEL_37:
                *v14 = v6;
                break;
              default:
                goto LABEL_38;
            }
            goto LABEL_38;
          case 3u:
            v4 = smdi_stream_state_flushing(v5, v4);
            v6 = 1;
            goto LABEL_25;
          case 4u:
            switch ( v4 )
            {
              case 0u:
                goto LABEL_13;
              case 2u:
              case 6u:
                goto LABEL_24;
              case 4u:
                v11 = *(void (__fastcall **)(_DWORD, int, int))(v5 + 144);
                if ( v11 )
                  v11(*(_DWORD *)(v5 + 148), 4, 1);
                goto LABEL_17;
              case 7u:
                **(_DWORD **)(v5 + 64) = 0;
                v10 = *(_DWORD *)(v5 + 64);
                *(_DWORD *)(v10 + 4) = 0;
                *(_DWORD *)(v10 + 8) = 0;
                **(_DWORD **)(v5 + 60) = 1;
                v6 = 1;
                goto LABEL_25;
              default:
LABEL_17:
                v6 = 1;
                break;
            }
            goto LABEL_25;
          case 5u:
            switch ( v4 )
            {
              case 0u:
LABEL_13:
                smdi_stream_enter_closed_state(v5);
                v6 = 1;
                goto LABEL_25;
              case 2u:
              case 6u:
                goto LABEL_24;
              case 3u:
                **(_DWORD **)(v5 + 60) = 4;
                goto LABEL_20;
              default:
LABEL_20:
                v6 = 1;
                break;
            }
            goto LABEL_25;
          case 6u:
            if ( v4 >= 2 && (v4 <= 3 || v4 == 6) )
            {
LABEL_24:
              v12 = *(_DWORD *)(v5 + 332);
              *(_BYTE *)(v5 + 116) = 0;
              *(_DWORD *)(v5 + 196) = v12 - 4;
              v13 = *(void (__fastcall **)(int, int, int))(v5 + 152);
              *(_BYTE *)(v5 + 117) = 0;
              *(_BYTE *)(v5 + 118) = 0;
              *(_BYTE *)(v5 + 119) = 0;
              v13(v5 + 52, 4, 1);
              v6 = 1;
              v4 = 2;
              *(_BYTE *)(*(_DWORD *)(v5 + 60) + 8) = 0;
              *(_BYTE *)(*(_DWORD *)(v5 + 60) + 9) = 0;
              *(_BYTE *)(*(_DWORD *)(v5 + 60) + 10) = 0;
              **(_DWORD **)(v5 + 60) = 1;
            }
LABEL_25:
            if ( v8 == v4 )
            {
LABEL_38:
              v16 = smd_port_to_info[v3];
              if ( v16 && !*(_DWORD *)(v16 + 16) )
              {
                v17 = 1;
                goto LABEL_42;
              }
LABEL_41:
              v17 = 0;
              goto LABEL_42;
            }
            result = v112;
            break;
          default:
            fatal_error02("Invalid stream state %d %d", *(ULONG **)(v5 + 20), v7, 0);
        }
      }
    }
    switch ( (unsigned int)v1 )
    {
      case 0u:
        if ( v2 == (ULONG *)1 || v2 == (ULONG *)2 || v2 == (ULONG *)3 )
        {
          v75 = **(_DWORD **)(result + 8);
          if ( v75 != 4 && v75 != 5 && v75 != 6 )
          {
            v18 = *(_DWORD *)result;
            v76 = 2;
            info = smd_port_to_info[*(_DWORD *)result];
            v21 = 1;
            while ( 1 )
            {
              v77 = **(ULONG ***)(result + 8);
              v78 = v76;
              if ( v76 == 3 )
              {
                v79 = *(void (**)(void))(result + 124);
                if ( v79 )
                {
                  v79();
                  v21 = 1;
                }
              }
              switch ( (unsigned int)v77 )
              {
                case 0u:
                  v76 = smdi_stream_state_closed(info, v76);
                  v21 = 1;
                  goto LABEL_265;
                case 1u:
                  switch ( v76 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 2u:
                      goto LABEL_71;
                    case 4u:
                      goto LABEL_108;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 2u:
                  switch ( v76 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 3u:
                      goto LABEL_75;
                    case 4u:
                      goto LABEL_110;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 3u:
                  v76 = smdi_stream_state_flushing(info, v76);
                  v21 = 1;
                  goto LABEL_265;
                case 4u:
                  switch ( v76 )
                  {
                    case 0u:
                      goto LABEL_253;
                    case 2u:
                    case 6u:
                      goto LABEL_264;
                    case 4u:
                      v81 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                      if ( v81 )
                        v81(*(_DWORD *)(info + 148), 4, 1);
                      goto LABEL_257;
                    case 7u:
                      **(_DWORD **)(info + 64) = 0;
                      v80 = *(_DWORD *)(info + 64);
                      *(_DWORD *)(v80 + 4) = 0;
                      *(_DWORD *)(v80 + 8) = 0;
                      **(_DWORD **)(info + 60) = 1;
                      v21 = 1;
                      goto LABEL_265;
                    default:
LABEL_257:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_265;
                case 5u:
                  switch ( v76 )
                  {
                    case 0u:
LABEL_253:
                      smdi_stream_enter_closed_state(info);
                      v21 = 1;
                      goto LABEL_265;
                    case 2u:
                    case 6u:
                      goto LABEL_264;
                    case 3u:
                      **(_DWORD **)(info + 60) = 4;
                      goto LABEL_260;
                    default:
LABEL_260:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_265;
                case 6u:
                  if ( v76 >= 2 && (v76 <= 3 || v76 == 6) )
                  {
LABEL_264:
                    v82 = *(void (__fastcall **)(int))(info + 152);
                    *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                    *(_BYTE *)(info + 116) = 0;
                    *(_BYTE *)(info + 117) = 0;
                    *(_BYTE *)(info + 118) = 0;
                    *(_BYTE *)(info + 119) = 0;
                    v82(info + 52);
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                    v21 = 1;
                    v76 = 2;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                    **(_DWORD **)(info + 60) = 1;
                  }
LABEL_265:
                  if ( v78 == v76 )
                    goto LABEL_78;
                  result = v112;
                  break;
                default:
                  fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v77, 0);
              }
            }
          }
          v18 = *(_DWORD *)result;
          v83 = 6;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v84 = **(ULONG ***)(result + 8);
            v85 = v83;
            if ( v83 == 3 )
            {
              v86 = *(void (**)(void))(result + 124);
              if ( v86 )
              {
                v86();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v84 )
            {
              case 0u:
                v83 = smdi_stream_state_closed(info, v83);
                v21 = 1;
                goto LABEL_289;
              case 1u:
                switch ( v83 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( v83 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                v83 = smdi_stream_state_flushing(info, v83);
                v21 = 1;
                goto LABEL_289;
              case 4u:
                switch ( v83 )
                {
                  case 0u:
                    goto LABEL_277;
                  case 2u:
                  case 6u:
                    goto LABEL_288;
                  case 4u:
                    v88 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v88 )
                      v88(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_281;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v87 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v87 + 4) = 0;
                    *(_DWORD *)(v87 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_289;
                  default:
LABEL_281:
                    v21 = 1;
                    break;
                }
                goto LABEL_289;
              case 5u:
                switch ( v83 )
                {
                  case 0u:
LABEL_277:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_289;
                  case 2u:
                  case 6u:
                    goto LABEL_288;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_284;
                  default:
LABEL_284:
                    v21 = 1;
                    break;
                }
                goto LABEL_289;
              case 6u:
                if ( v83 >= 2 && (v83 <= 3 || v83 == 6) )
                {
LABEL_288:
                  v89 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v89(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  v83 = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_289:
                if ( v85 == v83 )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v84, 0);
            }
          }
        }
        if ( v2 == (ULONG *)6 )
        {
          v18 = *(_DWORD *)result;
          v68 = 3;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v69 = **(ULONG ***)(result + 8);
            v70 = v68;
            if ( v68 == 3 )
            {
              v71 = *(void (**)(void))(result + 124);
              if ( v71 )
              {
                v71();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v69 )
            {
              case 0u:
                v68 = smdi_stream_state_closed(info, v68);
                v21 = 1;
                goto LABEL_238;
              case 1u:
                switch ( v68 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( v68 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                v68 = smdi_stream_state_flushing(info, v68);
                v21 = 1;
                goto LABEL_238;
              case 4u:
                switch ( v68 )
                {
                  case 0u:
                    goto LABEL_226;
                  case 2u:
                  case 6u:
                    goto LABEL_237;
                  case 4u:
                    v73 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v73 )
                      v73(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_230;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v72 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v72 + 4) = 0;
                    *(_DWORD *)(v72 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_238;
                  default:
LABEL_230:
                    v21 = 1;
                    break;
                }
                goto LABEL_238;
              case 5u:
                switch ( v68 )
                {
                  case 0u:
LABEL_226:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_238;
                  case 2u:
                  case 6u:
                    goto LABEL_237;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_233;
                  default:
LABEL_233:
                    v21 = 1;
                    break;
                }
                goto LABEL_238;
              case 6u:
                if ( v68 >= 2 && (v68 <= 3 || v68 == 6) )
                {
LABEL_237:
                  v74 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v74(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  v68 = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_238:
                if ( v70 == v68 )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v69, 0);
            }
          }
        }
        goto LABEL_366;
      case 1u:
        if ( v2 == (ULONG *)2 || v2 == (ULONG *)3 )
        {
          v18 = *(_DWORD *)result;
          v19 = 2;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v22 = **(ULONG ***)(result + 8);
            v23 = v19;
            if ( v19 == 3 )
            {
              v24 = *(void (**)(void))(result + 124);
              if ( v24 )
              {
                v24();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v22 )
            {
              case 0u:
                v19 = smdi_stream_state_closed(info, v19);
                v21 = 1;
                goto LABEL_67;
              case 1u:
                switch ( v19 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( v19 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                v19 = smdi_stream_state_flushing(info, v19);
                v21 = 1;
                goto LABEL_67;
              case 4u:
                switch ( v19 )
                {
                  case 0u:
                    goto LABEL_55;
                  case 2u:
                  case 6u:
                    goto LABEL_66;
                  case 4u:
                    v26 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v26 )
                      v26(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_59;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v25 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v25 + 4) = 0;
                    *(_DWORD *)(v25 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_67;
                  default:
LABEL_59:
                    v21 = 1;
                    break;
                }
                goto LABEL_67;
              case 5u:
                switch ( v19 )
                {
                  case 0u:
LABEL_55:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_67;
                  case 2u:
                  case 6u:
                    goto LABEL_66;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_62;
                  default:
LABEL_62:
                    v21 = 1;
                    break;
                }
                goto LABEL_67;
              case 6u:
                if ( v19 >= 2 && (v19 <= 3 || v19 == 6) )
                {
LABEL_66:
                  v27 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v27(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  v19 = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_67:
                if ( v23 == v19 )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v22, 0);
            }
          }
        }
        goto LABEL_366;
      case 2u:
        if ( v2 == (ULONG *)3 )
        {
          v31 = **(_DWORD **)(result + 8);
          if ( v31 != 4 && v31 != 5 && v31 != 6 )
          {
            v18 = *(_DWORD *)result;
            v32 = 2;
            info = smd_port_to_info[*(_DWORD *)result];
            v21 = 1;
            while ( 1 )
            {
              v33 = **(ULONG ***)(result + 8);
              v34 = v32;
              if ( v32 == 3 )
              {
                v35 = *(void (**)(void))(result + 124);
                if ( v35 )
                {
                  v35();
                  v21 = 1;
                }
              }
              switch ( (unsigned int)v33 )
              {
                case 0u:
                  v32 = smdi_stream_state_closed(info, v32);
                  v21 = 1;
                  goto LABEL_105;
                case 1u:
                  switch ( v32 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 2u:
                      goto LABEL_71;
                    case 4u:
                      goto LABEL_108;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 2u:
                  switch ( v32 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 3u:
                      goto LABEL_75;
                    case 4u:
                      goto LABEL_110;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 3u:
                  v32 = smdi_stream_state_flushing(info, v32);
                  v21 = 1;
                  goto LABEL_105;
                case 4u:
                  switch ( v32 )
                  {
                    case 0u:
                      goto LABEL_93;
                    case 2u:
                    case 6u:
                      goto LABEL_104;
                    case 4u:
                      v37 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                      if ( v37 )
                        v37(*(_DWORD *)(info + 148), 4, 1);
                      goto LABEL_97;
                    case 7u:
                      **(_DWORD **)(info + 64) = 0;
                      v36 = *(_DWORD *)(info + 64);
                      *(_DWORD *)(v36 + 4) = 0;
                      *(_DWORD *)(v36 + 8) = 0;
                      **(_DWORD **)(info + 60) = 1;
                      v21 = 1;
                      goto LABEL_105;
                    default:
LABEL_97:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_105;
                case 5u:
                  switch ( v32 )
                  {
                    case 0u:
LABEL_93:
                      smdi_stream_enter_closed_state(info);
                      v21 = 1;
                      goto LABEL_105;
                    case 2u:
                    case 6u:
                      goto LABEL_104;
                    case 3u:
                      **(_DWORD **)(info + 60) = 4;
                      goto LABEL_100;
                    default:
LABEL_100:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_105;
                case 6u:
                  if ( v32 >= 2 && (v32 <= 3 || v32 == 6) )
                  {
LABEL_104:
                    v38 = *(void (__fastcall **)(int))(info + 152);
                    *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                    *(_BYTE *)(info + 116) = 0;
                    *(_BYTE *)(info + 117) = 0;
                    *(_BYTE *)(info + 118) = 0;
                    *(_BYTE *)(info + 119) = 0;
                    v38(info + 52);
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                    v21 = 1;
                    v32 = 2;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                    **(_DWORD **)(info + 60) = 1;
                  }
LABEL_105:
                  if ( v34 == v32 )
                    goto LABEL_78;
                  result = v112;
                  break;
                default:
                  fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v33, 0);
              }
            }
          }
          v18 = *(_DWORD *)result;
          v39 = 6;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v40 = **(ULONG ***)(result + 8);
            v41 = v39;
            if ( v39 == 3 )
            {
              v42 = *(void (**)(void))(result + 124);
              if ( v42 )
              {
                v42();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v40 )
            {
              case 0u:
                v39 = smdi_stream_state_closed(info, v39);
                v21 = 1;
                goto LABEL_131;
              case 1u:
                switch ( v39 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( v39 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                v39 = smdi_stream_state_flushing(info, v39);
                v21 = 1;
                goto LABEL_131;
              case 4u:
                switch ( v39 )
                {
                  case 0u:
                    goto LABEL_119;
                  case 2u:
                  case 6u:
                    goto LABEL_130;
                  case 4u:
                    v44 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v44 )
                      v44(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_123;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v43 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v43 + 4) = 0;
                    *(_DWORD *)(v43 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_131;
                  default:
LABEL_123:
                    v21 = 1;
                    break;
                }
                goto LABEL_131;
              case 5u:
                switch ( v39 )
                {
                  case 0u:
LABEL_119:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_131;
                  case 2u:
                  case 6u:
                    goto LABEL_130;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_126;
                  default:
LABEL_126:
                    v21 = 1;
                    break;
                }
                goto LABEL_131;
              case 6u:
                if ( v39 >= 2 && (v39 <= 3 || v39 == 6) )
                {
LABEL_130:
                  v45 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v45(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  v39 = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_131:
                if ( v41 == v39 )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v40, 0);
            }
          }
        }
        goto LABEL_366;
      case 3u:
        if ( v2 == (ULONG *)2 )
        {
          v46 = **(_DWORD **)(result + 8);
          if ( v46 != 4 && v46 != 5 && v46 != 6 )
          {
            v18 = *(_DWORD *)result;
            v47 = 2;
            info = smd_port_to_info[*(_DWORD *)result];
            v21 = 1;
            while ( 1 )
            {
              v48 = **(ULONG ***)(result + 8);
              v49 = v47;
              if ( v47 == 3 )
              {
                v50 = *(void (**)(void))(result + 124);
                if ( v50 )
                {
                  v50();
                  v21 = 1;
                }
              }
              switch ( (unsigned int)v48 )
              {
                case 0u:
                  v47 = smdi_stream_state_closed(info, v47);
                  v21 = 1;
                  goto LABEL_159;
                case 1u:
                  switch ( v47 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 2u:
                      goto LABEL_71;
                    case 4u:
                      goto LABEL_108;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 2u:
                  switch ( v47 )
                  {
                    case 0u:
                      goto LABEL_70;
                    case 3u:
                      goto LABEL_75;
                    case 4u:
                      goto LABEL_110;
                    case 7u:
                      goto LABEL_76;
                    default:
                      goto LABEL_78;
                  }
                  goto LABEL_78;
                case 3u:
                  v47 = smdi_stream_state_flushing(info, v47);
                  v21 = 1;
                  goto LABEL_159;
                case 4u:
                  switch ( v47 )
                  {
                    case 0u:
                      goto LABEL_147;
                    case 2u:
                    case 6u:
                      goto LABEL_158;
                    case 4u:
                      v52 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                      if ( v52 )
                        v52(*(_DWORD *)(info + 148), 4, 1);
                      goto LABEL_151;
                    case 7u:
                      **(_DWORD **)(info + 64) = 0;
                      v51 = *(_DWORD *)(info + 64);
                      *(_DWORD *)(v51 + 4) = 0;
                      *(_DWORD *)(v51 + 8) = 0;
                      **(_DWORD **)(info + 60) = 1;
                      v21 = 1;
                      goto LABEL_159;
                    default:
LABEL_151:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_159;
                case 5u:
                  switch ( v47 )
                  {
                    case 0u:
LABEL_147:
                      smdi_stream_enter_closed_state(info);
                      v21 = 1;
                      goto LABEL_159;
                    case 2u:
                    case 6u:
                      goto LABEL_158;
                    case 3u:
                      **(_DWORD **)(info + 60) = 4;
                      goto LABEL_154;
                    default:
LABEL_154:
                      v21 = 1;
                      break;
                  }
                  goto LABEL_159;
                case 6u:
                  if ( v47 >= 2 && (v47 <= 3 || v47 == 6) )
                  {
LABEL_158:
                    v53 = *(void (__fastcall **)(int))(info + 152);
                    *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                    *(_BYTE *)(info + 116) = 0;
                    *(_BYTE *)(info + 117) = 0;
                    *(_BYTE *)(info + 118) = 0;
                    *(_BYTE *)(info + 119) = 0;
                    v53(info + 52);
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                    v21 = 1;
                    v47 = 2;
                    *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                    **(_DWORD **)(info + 60) = 1;
                  }
LABEL_159:
                  if ( v49 == v47 )
                    goto LABEL_78;
                  result = v112;
                  break;
                default:
                  fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v48, 0);
              }
            }
          }
          v18 = *(_DWORD *)result;
          v54 = 6;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v55 = **(ULONG ***)(result + 8);
            v56 = v54;
            if ( v54 == 3 )
            {
              v57 = *(void (**)(void))(result + 124);
              if ( v57 )
              {
                v57();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v55 )
            {
              case 0u:
                v54 = smdi_stream_state_closed(info, v54);
                v21 = 1;
                goto LABEL_183;
              case 1u:
                switch ( v54 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( v54 )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                v54 = smdi_stream_state_flushing(info, v54);
                v21 = 1;
                goto LABEL_183;
              case 4u:
                switch ( v54 )
                {
                  case 0u:
                    goto LABEL_171;
                  case 2u:
                  case 6u:
                    goto LABEL_182;
                  case 4u:
                    v59 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v59 )
                      v59(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_175;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v58 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v58 + 4) = 0;
                    *(_DWORD *)(v58 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_183;
                  default:
LABEL_175:
                    v21 = 1;
                    break;
                }
                goto LABEL_183;
              case 5u:
                switch ( v54 )
                {
                  case 0u:
LABEL_171:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_183;
                  case 2u:
                  case 6u:
                    goto LABEL_182;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_178;
                  default:
LABEL_178:
                    v21 = 1;
                    break;
                }
                goto LABEL_183;
              case 6u:
                if ( v54 >= 2 && (v54 <= 3 || v54 == 6) )
                {
LABEL_182:
                  v60 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v60(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  v54 = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_183:
                if ( v56 == v54 )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v55, 0);
            }
          }
        }
        goto LABEL_366;
      case 4u:
        if ( v2 == (ULONG *)2 || v2 == (ULONG *)1 || v2 == (ULONG *)3 )
        {
          v18 = *(_DWORD *)result;
          event = 2;
          info = smd_port_to_info[*(_DWORD *)result];
          v21 = 1;
          while ( 1 )
          {
            v62 = **(ULONG ***)(result + 8);
            v63 = event;
            if ( event == 3 )
            {
              v64 = *(void (**)(void))(result + 124);
              if ( v64 )
              {
                v64();
                v21 = 1;
              }
            }
            switch ( (unsigned int)v62 )
            {
              case 0u:
                event = smdi_stream_state_closed(info, event);
                v21 = 1;
                goto LABEL_210;
              case 1u:
                switch ( event )
                {
                  case 0u:
                    goto LABEL_70;
                  case 2u:
                    goto LABEL_71;
                  case 4u:
                    goto LABEL_108;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 2u:
                switch ( event )
                {
                  case 0u:
                    goto LABEL_70;
                  case 3u:
                    goto LABEL_75;
                  case 4u:
                    goto LABEL_110;
                  case 7u:
                    goto LABEL_76;
                  default:
                    goto LABEL_78;
                }
                goto LABEL_78;
              case 3u:
                event = smdi_stream_state_flushing(info, event);
                v21 = 1;
                goto LABEL_210;
              case 4u:
                switch ( event )
                {
                  case 0u:
                    goto LABEL_198;
                  case 2u:
                  case 6u:
                    goto LABEL_209;
                  case 4u:
                    v66 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
                    if ( v66 )
                      v66(*(_DWORD *)(info + 148), 4, 1);
                    goto LABEL_202;
                  case 7u:
                    **(_DWORD **)(info + 64) = 0;
                    v65 = *(_DWORD *)(info + 64);
                    *(_DWORD *)(v65 + 4) = 0;
                    *(_DWORD *)(v65 + 8) = 0;
                    **(_DWORD **)(info + 60) = 1;
                    v21 = 1;
                    goto LABEL_210;
                  default:
LABEL_202:
                    v21 = 1;
                    break;
                }
                goto LABEL_210;
              case 5u:
                switch ( event )
                {
                  case 0u:
LABEL_198:
                    smdi_stream_enter_closed_state(info);
                    v21 = 1;
                    goto LABEL_210;
                  case 2u:
                  case 6u:
                    goto LABEL_209;
                  case 3u:
                    **(_DWORD **)(info + 60) = 4;
                    goto LABEL_205;
                  default:
LABEL_205:
                    v21 = 1;
                    break;
                }
                goto LABEL_210;
              case 6u:
                if ( event >= 2 && (event <= 3 || event == 6) )
                {
LABEL_209:
                  v67 = *(void (__fastcall **)(int))(info + 152);
                  *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
                  *(_BYTE *)(info + 116) = 0;
                  *(_BYTE *)(info + 117) = 0;
                  *(_BYTE *)(info + 118) = 0;
                  *(_BYTE *)(info + 119) = 0;
                  v67(info + 52);
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
                  v21 = 1;
                  event = 2;
                  *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
                  **(_DWORD **)(info + 60) = 1;
                }
LABEL_210:
                if ( v63 == event )
                  goto LABEL_78;
                result = v112;
                break;
              default:
                fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v62, 0);
            }
          }
        }
        goto LABEL_366;
      case 5u:
        if ( v2 != (ULONG *)2 && v2 != (ULONG *)1 && v2 != (ULONG *)3 )
          goto LABEL_366;
        v18 = *(_DWORD *)result;
        v90 = 2;
        info = smd_port_to_info[*(_DWORD *)result];
        v21 = 1;
        break;
      case 6u:
        if ( v2 != (ULONG *)1 && v2 != (ULONG *)2 && v2 != (ULONG *)3 )
          goto LABEL_366;
        smdi_stream_state_machine((int *)result, 2u);// event SMD_EVENT_REMOTE_OPEN
        *(_DWORD *)(v112 + 80) = v113;
        return v112;
      default:
        fatal_error02("Invalid stream state %d %d", *(ULONG **)result, v1, v2);
    }
    while ( 1 )
    {
      v91 = **(ULONG ***)(result + 8);
      v92 = v90;
      if ( v90 == 3 )
      {
        v93 = *(void (**)(void))(result + 124);
        if ( v93 )
        {
          v93();
          v21 = 1;
        }
      }
      switch ( (unsigned int)v91 )
      {
        case 0u:
          v90 = smdi_stream_state_closed(info, v90);
          v21 = 1;
          goto LABEL_316;
        case 1u:
          switch ( v90 )
          {
            case 0u:
              goto LABEL_70;
            case 2u:
LABEL_71:
              v28 = *(int **)(info + 60);
              if ( *(_BYTE *)(info + 129) )
              {
                *(_BYTE *)(info + 129) = 0;
                v21 = 3;
              }
              else
              {
                v21 = 2;
              }
              goto LABEL_77;
            case 4u:
LABEL_108:
              *(_BYTE *)(info + 129) = 1;
              break;
            case 7u:
              goto LABEL_76;
            default:
              goto LABEL_78;
          }
          goto LABEL_78;
        case 2u:
          switch ( v90 )
          {
            case 0u:
LABEL_70:
              smdi_stream_enter_closed_state(info);
              break;
            case 3u:
LABEL_75:
              **(_DWORD **)(info + 60) = 4;
              break;
            case 4u:
LABEL_110:
              **(_DWORD **)(info + 60) = 3;
              *(_BYTE *)(*(_DWORD *)(info + 60) + 11) = 0;
              break;
            case 7u:
LABEL_76:
              **(_DWORD **)(info + 64) = 0;
              v29 = *(_DWORD *)(info + 64);
              *(_DWORD *)(v29 + 4) = 0;
              *(_DWORD *)(v29 + 8) = 0;
              v28 = *(int **)(info + 60);
LABEL_77:
              *v28 = v21;
              break;
            default:
              goto LABEL_78;
          }
          goto LABEL_78;
        case 3u:
          v90 = smdi_stream_state_flushing(info, v90);
          v21 = 1;
          goto LABEL_316;
        case 4u:
          switch ( v90 )
          {
            case 0u:
              goto LABEL_304;
            case 2u:
            case 6u:
              goto LABEL_315;
            case 4u:
              v95 = *(void (__fastcall **)(_DWORD, int, int))(info + 144);
              if ( v95 )
                v95(*(_DWORD *)(info + 148), 4, 1);
              goto LABEL_308;
            case 7u:
              **(_DWORD **)(info + 64) = 0;
              v94 = *(_DWORD *)(info + 64);
              *(_DWORD *)(v94 + 4) = 0;
              *(_DWORD *)(v94 + 8) = 0;
              **(_DWORD **)(info + 60) = 1;
              v21 = 1;
              goto LABEL_316;
            default:
LABEL_308:
              v21 = 1;
              break;
          }
          goto LABEL_316;
        case 5u:
          switch ( v90 )
          {
            case 0u:
LABEL_304:
              smdi_stream_enter_closed_state(info);
              v21 = 1;
              goto LABEL_316;
            case 2u:
            case 6u:
              goto LABEL_315;
            case 3u:
              **(_DWORD **)(info + 60) = 4;
              goto LABEL_311;
            default:
LABEL_311:
              v21 = 1;
              break;
          }
          goto LABEL_316;
        case 6u:
          if ( v90 >= 2 && (v90 <= 3 || v90 == 6) )
          {
LABEL_315:
            v96 = *(void (__fastcall **)(int))(info + 152);
            *(_DWORD *)(info + 196) = *(_DWORD *)(info + 332) - 4;
            *(_BYTE *)(info + 116) = 0;
            *(_BYTE *)(info + 117) = 0;
            *(_BYTE *)(info + 118) = 0;
            *(_BYTE *)(info + 119) = 0;
            v96(info + 52);
            *(_BYTE *)(*(_DWORD *)(info + 60) + 8) = 0;
            *(_BYTE *)(*(_DWORD *)(info + 60) + 9) = 0;
            v21 = 1;
            v90 = 2;
            *(_BYTE *)(*(_DWORD *)(info + 60) + 10) = 0;
            **(_DWORD **)(info + 60) = 1;
          }
LABEL_316:
          if ( v92 == v90 )
          {
LABEL_78:
            v30 = smd_port_to_info[v18];
            if ( !v30 || *(_DWORD *)(v30 + 16) )
              goto LABEL_41;
            v17 = 1;
LABEL_42:
            result = v112;
            if ( v17 )
            {
LABEL_363:
              *(_BYTE *)(*(_DWORD *)(result + 8) + 10) = 1;
              smd_event_send(result);
              goto LABEL_364;
            }
            goto LABEL_365;
          }
          result = v112;
          break;
        default:
          fatal_error02("Invalid stream state %d %d", *(ULONG **)(info + 20), v91, 0);
      }
    }
  }
  v97 = *(_DWORD *)result;
  v98 = 3;
  v99 = smd_port_to_info[*(_DWORD *)result];
  v100 = 1;
  while ( 2 )
  {
    v101 = **(ULONG ***)(result + 8);
    v102 = v98;
    if ( v98 == 3 )
    {
      v103 = *(void (**)(void))(result + 124);
      if ( v103 )
      {
        v103();
        v100 = 1;
      }
    }
    switch ( (unsigned int)v101 )
    {
      case 0u:
        v98 = smdi_stream_state_closed(v99, v98);
        v100 = 1;
        goto LABEL_344;
      case 1u:
        switch ( v98 )
        {
          case 0u:
            goto LABEL_347;
          case 2u:
            v108 = *(int **)(v99 + 60);
            if ( *(_BYTE *)(v99 + 129) )
            {
              *(_BYTE *)(v99 + 129) = 0;
              v100 = 3;
            }
            else
            {
              v100 = 2;
            }
            goto LABEL_356;
          case 4u:
            *(_BYTE *)(v99 + 129) = 1;
            break;
          case 7u:
            goto LABEL_355;
          default:
            goto LABEL_357;
        }
        goto LABEL_357;
      case 2u:
        switch ( v98 )
        {
          case 0u:
LABEL_347:
            smdi_stream_enter_closed_state(v99);
            break;
          case 3u:
            **(_DWORD **)(v99 + 60) = 4;
            break;
          case 4u:
            **(_DWORD **)(v99 + 60) = 3;
            *(_BYTE *)(*(_DWORD *)(v99 + 60) + 11) = 0;
            break;
          case 7u:
LABEL_355:
            **(_DWORD **)(v99 + 64) = 0;
            v109 = *(_DWORD *)(v99 + 64);
            *(_DWORD *)(v109 + 4) = 0;
            *(_DWORD *)(v109 + 8) = 0;
            v108 = *(int **)(v99 + 60);
LABEL_356:
            *v108 = v100;
            break;
          default:
            goto LABEL_357;
        }
        goto LABEL_357;
      case 3u:
        v98 = smdi_stream_state_flushing(v99, v98);
        v100 = 1;
        goto LABEL_344;
      case 4u:
        switch ( v98 )
        {
          case 0u:
            goto LABEL_332;
          case 2u:
          case 6u:
            goto LABEL_343;
          case 4u:
            v105 = *(void (__fastcall **)(_DWORD, int, int))(v99 + 144);
            if ( v105 )
              v105(*(_DWORD *)(v99 + 148), 4, 1);
            goto LABEL_336;
          case 7u:
            **(_DWORD **)(v99 + 64) = 0;
            v104 = *(_DWORD *)(v99 + 64);
            *(_DWORD *)(v104 + 4) = 0;
            *(_DWORD *)(v104 + 8) = 0;
            **(_DWORD **)(v99 + 60) = 1;
            v100 = 1;
            goto LABEL_344;
          default:
LABEL_336:
            v100 = 1;
            break;
        }
        goto LABEL_344;
      case 5u:
        switch ( v98 )
        {
          case 0u:
LABEL_332:
            smdi_stream_enter_closed_state(v99);
            v100 = 1;
            goto LABEL_344;
          case 2u:
          case 6u:
            goto LABEL_343;
          case 3u:
            **(_DWORD **)(v99 + 60) = 4;
            goto LABEL_339;
          default:
LABEL_339:
            v100 = 1;
            break;
        }
        goto LABEL_344;
      case 6u:
        if ( v98 >= 2 && (v98 <= 3 || v98 == 6) )
        {
LABEL_343:
          v106 = *(_DWORD *)(v99 + 332);
          *(_BYTE *)(v99 + 116) = 0;
          *(_DWORD *)(v99 + 196) = v106 - 4;
          v107 = *(void (__fastcall **)(int, int, int))(v99 + 152);
          *(_BYTE *)(v99 + 117) = 0;
          *(_BYTE *)(v99 + 118) = 0;
          *(_BYTE *)(v99 + 119) = 0;
          v107(v99 + 52, 4, 1);
          v100 = 1;
          v98 = 2;
          *(_BYTE *)(*(_DWORD *)(v99 + 60) + 8) = 0;
          *(_BYTE *)(*(_DWORD *)(v99 + 60) + 9) = 0;
          *(_BYTE *)(*(_DWORD *)(v99 + 60) + 10) = 0;
          **(_DWORD **)(v99 + 60) = 1;
        }
LABEL_344:
        if ( v102 != v98 )
        {
          result = v112;
          continue;
        }
LABEL_357:
        v110 = smd_port_to_info[v97];
        if ( v110 && !*(_DWORD *)(v110 + 16) )
        {
          result = v112;
          goto LABEL_363;
        }
LABEL_364:
        result = v112;
LABEL_365:
        v2 = v113;
LABEL_366:
        *(_DWORD *)(result + 80) = v2;
        return result;
      default:
        fatal_error02("Invalid stream state %d %d", *(ULONG **)(v99 + 20), v101, 0);
    }
  }
}


// Function: smdi_add_channel_info
int __fastcall smdi_add_channel_info(int result, char *name, int a3, int a4, int a5)
{
  ULONG *v6; // r4
  int v7; // r10
  int v8; // r5
  int v9; // r7

  v6 = (ULONG *)result;
  v7 = dword_4159FC + 32 * result;
  if ( smem_spin_lock )
    result = smem_spin_lock(3);                 // sub_402994 of qcsmem8930
  v8 = dword_4159FC;
  if ( !*(_BYTE *)v7 )
  {
    v9 = dword_4159FC + 32 * (_DWORD)v6;
    *(_DWORD *)(v9 + 20) = v6;
    if ( name )
    {
      result = strlen(name);
      if ( (unsigned int)(result + 1) <= 0x14 )
      {
        result = memcpy_forward_new(v7, (unsigned int)name, result + 1);
      }
      else
      {
        *(_DWORD *)v7 = *(_DWORD *)name;
        *(_DWORD *)(v7 + 4) = *((_DWORD *)name + 1);
        *(_DWORD *)(v7 + 8) = *((_DWORD *)name + 2);
        *(_DWORD *)(v7 + 12) = *((_DWORD *)name + 3);
        *(_WORD *)(v7 + 16) = *((_WORD *)name + 8);
        *(_BYTE *)(v7 + 18) = name[18];
        *(_BYTE *)(v7 + 19) = 0;
      }
    }
    *(_DWORD *)(v9 + 24) |= (a5 << 8) | a3;
  }
  ++*(_DWORD *)(v8 + 32 * (_DWORD)v6 + 28);
  if ( smem_spin_unlock )
  {
    result = ((int (__fastcall *)(int))smem_spin_unlock)(3);
    v8 = dword_4159FC;
  }
  if ( (*(_DWORD *)(v8 + 32 * (_DWORD)v6 + 24) & 0xF000) != 0 )
    fatal_error02("smdi_add_channel_info: channel %d protocol mismatch", v6, 0, 0);
  if ( a5 )
  {
    if ( (*(_DWORD *)(v8 + 32 * (_DWORD)v6 + 24) & 0xF00) != a5 << 8 )
      fatal_error02("smdi_add_channel_info: channel %d xfrflow type mismatch", v6, 0, 0);
  }
  return result;
}


// Function: smdi_alloc_channel_info
unsigned int __fastcall smdi_alloc_channel_info(
        char *name,
        smd_channel_type channel_type,
        smd_channel_protocol_type protocol,
        smd_xfrflow_type xfrflow)
{
  int v4; // r5
  char **v7; // r6
  unsigned int i; // r4
  char *v9; // t1
  int v10; // r3
  int v11; // r4
  int v12; // r10
  char *v13; // r8
  int v14; // t1
  int v15; // r3
  int v16; // r1
  int v17; // r2
  int v18; // r3
  int v19; // r6
  smd_xfrflow_type v20; // r8
  int error_type; // r6
  int v23; // r4
  unsigned int v24; // r2
  _DWORD v27[6]; // [sp+10h] [bp-38h] BYREF

  v4 = 64;
  if ( channel_type == SMD_CHANNEL_TYPE_FIRST )
  {
    v7 = (char **)&smd_port_to_name;
    for ( i = 0; i < 4; ++i )                   // 4=SMD_NUM_PORTS
    {
      v9 = *v7++;
      if ( !strncmp(v9, name, 19u) )            // 19=SMD_CHANNEL_NAME_SIZE_MAX-1
      {
        smdi_add_channel_info(i, name, 0, v10, xfrflow);
        return i;
      }
    }
  }
  if ( smem_spin_lock )
    smem_spin_lock(3);                          // sub_402994(3=SMEM_SPINLOCK_SMEM_ALLOC) of qcsmem8930
  v11 = 4;                                      // 4=SMD_NUM_PORTS
  v12 = dword_4159FC;
  v13 = (char *)(dword_4159FC + 128);
  while ( 1 )
  {
    v14 = *v13;
    v13 += 32;
    if ( !v14 )
    {
      if ( v4 == 64 )                           // 64=SMEM_NUM_SMD_CHANNELS
        v4 = v11;
      goto LABEL_20;
    }
    v15 = *((_DWORD *)v13 - 7);
    v16 = *((_DWORD *)v13 - 6);
    v27[0] = *((_DWORD *)v13 - 8);
    v17 = *((_DWORD *)v13 - 5);
    v27[1] = v15;
    v18 = *((_DWORD *)v13 - 4);
    v27[3] = v17;
    v27[2] = v16;
    v19 = *((_DWORD *)v13 - 2);
    v27[4] = v18;
    if ( !strncmp((char *)v27, name, 0x13u) && (unsigned __int8)v19 == channel_type )
      break;
LABEL_20:
    if ( (unsigned int)++v11 >= 64 )
    {
      v20 = xfrflow;
      goto LABEL_22;
    }
  }
  v20 = xfrflow;
  v4 = v11;
  if ( (v19 & 0xF00) == 0 )
  {
    v19 |= xfrflow << 8;
    *(_DWORD *)(v12 + 32 * v11 + 24) = v19;
  }
  if ( xfrflow && (v19 & 0xF00) != xfrflow << 8 || (v19 & 0xF000) != 0 )
  {
    error_type = 1;
    goto LABEL_23;
  }
  ++*(_DWORD *)(v12 + 32 * v11 + 28);
LABEL_22:
  error_type = 0;
LABEL_23:
  if ( v11 == 64 )
  {
    if ( v4 == 64 )
    {
      error_type = 2;
    }
    else
    {
      v23 = v12 + 32 * v4;
      *(_DWORD *)(v23 + 20) = v4;
      if ( v23 && name )
      {
        v24 = strlen(name) + 1;
        if ( v24 > 20 )
        {
          *(_DWORD *)v23 = *(_DWORD *)name;
          *(_DWORD *)(v23 + 4) = *((_DWORD *)name + 1);
          *(_DWORD *)(v23 + 8) = *((_DWORD *)name + 2);
          *(_DWORD *)(v23 + 12) = *((_DWORD *)name + 3);
          *(_WORD *)(v23 + 16) = *((_WORD *)name + 8);
          *(_BYTE *)(v23 + 18) = name[18];
          *(_BYTE *)(v23 + 19) = 0;
          *(_DWORD *)(v23 + 24) = channel_type | (v20 << 8);
          ++*(_DWORD *)(v23 + 28);
          goto LABEL_33;
        }
        memcpy_forward_new(v12 + 32 * v4, (unsigned int)name, v24);
      }
      *(_DWORD *)(v23 + 24) = channel_type | (v20 << 8);
      ++*(_DWORD *)(v23 + 28);
    }
  }
LABEL_33:
  if ( smem_spin_unlock )
    ((void (__fastcall *)(int))smem_spin_unlock)(3);// 3=SMEM_SPINLOCK_SMEM_ALLOC
  if ( error_type == 1 )                        // 1=SMDI_CHANNEL_PROPERTIES_MISMATCH
    fatal_error02("smdi_alloc_channel_info: channel %d protocol mismatch", (ULONG *)v4, 0, 0);
  if ( error_type == 2 )                        // 2=SMDI_CHANNEL_TABLE_FULL
    fatal_error02("smdi_alloc_channel_info: SMD channel table is full", 0, 0, 0);
  return v4;
}


// Function: smdi_allocate_stream_channel
// Allocate a streaming shared memory channel and connect the tx and rx connects to be consistent with the other processor.
// 
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_internal.c#L1959
ULONG *__fastcall smdi_allocate_stream_channel(int *port_id, smd_stream_info_struct *info)
{
  smd_channel_type channel_type; // r2
  smd_shared_stream_info_type *v5; // r5
  ULONG fifo_sz; // r1
  ULONG *proc0_fifo; // r0
  ULONG *proc1_fifo; // r2

  channel_type = info->channel_type;
  if ( *((_DWORD *)&smdi_edges.to + 2 * channel_type) && *(&smdi_edges.processor + 2 * channel_type) )
    fatal_error02(
      "SMD port %d: channel type %d is not coincident with host %d",
      (ULONG *)port_id,
      (ULONG *)channel_type,
      0);                                       // SMD_THIS_HOST
  if ( !SMEM_ioctl42000_outputbuffer_size52
    || (v5 = (smd_shared_stream_info_type *)SMEM_ioctl42000_outputbuffer_size52((char *)port_id + 14, 40)) == 0 )// smem_alloc(SMEM_SMD_BASE_ID + port_id, 40)
  {
    fatal_error02("Unable to allocate channel for %d", (ULONG *)port_id, 0, 0);
  }
  fifo_sz = info->fifo_sz;
  if ( (fifo_sz & 0x1F) != 0 || fifo_sz < 0x400 || fifo_sz > 0x20000 )
    fatal_error02("Invalid SMD FIFO SZ: %i", (ULONG *)fifo_sz, 0, 0);
  if ( !SMEM_ioctl42000_outputbuffer_size52
    || (proc0_fifo = (ULONG *)SMEM_ioctl42000_outputbuffer_size52((char *)port_id + 338, 2 * fifo_sz)) == 0 )// smem_alloc(SMEM_SMD_FIFO_BASE_ID+port_id, 2 * fifo_sz) of qcsmem8930
  {
    fatal_error02("Unable to allocate FIFOs for port %d", (ULONG *)port_id, 0, 0);
  }
  proc1_fifo = (ULONG *)((char *)proc0_fifo + info->fifo_sz);
  if ( *((_DWORD *)&smdi_edges.to + 2 * info->channel_type) )// smdi_edges[info->channel_type].host0 != SMD_THIS_HOST
  {
    info->tx_shared_info_ptr = v5 + 1;
    info->tx_shared_fifo = proc1_fifo;
    info->rx_shared_info_ptr = v5;
    info->rx_shared_fifo = proc0_fifo;
  }
  else
  {
    info->rx_shared_info_ptr = v5 + 1;
    info->tx_shared_info_ptr = v5;
    info->tx_shared_fifo = proc0_fifo;
    info->rx_shared_fifo = proc1_fifo;
  }
  return proc0_fifo;
}


// Function: SmdGetPortInfo
// This function is responsible for retrieving or initializing information about an SMD port based on an index. It first checks a cache. If not cached, it extracts port-related details from a global structure, populates a local information structure, and potentially calls a callback to get additional data.
int *__fastcall SmdGetPortInfo(int a1, int a2, int a3, int a4)
{
  int v4; // r2
  int v7; // r0
  int *v8; // r6
  int v9; // r7
  int v10; // r3
  int v11; // [sp+0h] [bp-18h] BYREF

  v11 = a4;
  v4 = 3 * a1;
  if ( dword_415320[6 * a1 + 1] != -1 )
    return &dword_415320[6 * a1];
  v7 = dword_4159FC;
  if ( !*(_BYTE *)(32 * a1 + dword_4159FC) )
    return 0;
  v8 = &dword_415320[2 * v4];
  v8[1] = a1;
  if ( smem_spin_lock )
  {
    smem_spin_lock(3);
    v7 = dword_4159FC;
  }
  v9 = *(_DWORD *)(32 * a1 + v7 + 24);
  if ( smem_spin_unlock )
    ((void (__fastcall *)(int))smem_spin_unlock)(3);
  *v8 = v9 & 0xF000;
  v10 = *((_DWORD *)&smdi_edges.to + 2 * (unsigned __int8)v9);
  v8[2] = (unsigned __int8)v9;
  v8[3] = v10;
  v8[4] = *(&smdi_edges.processor + 2 * (unsigned __int8)v9);
  if ( smem_get_addr )
    v8[5] = smem_get_addr(a1 + 14, &v11);       // sub_402308 of qcsmem8930
  else
    v8[5] = 0;
  return v8;
}


// Function: fatal_error01
void __noreturn fatal_error(CHAR *a1, ULONG *a2, int a3, int a4, ...)
{
  DbgPrintEx(0x4Du, 0, a1, a2, 0, 0, a4);
  KeBugCheckEx(0x121u, a2, 0, 0, 0);
}


// Function: SmdProcessSignalChanges
// This function is a signal change detection and dispatching function for SMD communication. It monitors the state of various communication signals (like DTR, CTS, CD, RI) and, when a change is detected, it invokes registered callback functions to handle these changes.
int __fastcall sub_409864(int result)
{
  int v1; // r4
  int v2; // r2
  int (*v3)(void); // r3
  int (__fastcall *v4)(int); // r3
  int (__fastcall *v5)(_DWORD); // r3
  int v6; // r2
  int (__fastcall *v7)(_DWORD); // r3
  int v8; // r2
  int (__fastcall *v9)(_DWORD); // r3
  int v10; // r5
  int (__fastcall *v11)(_DWORD); // r3

  v1 = result;
  v2 = *(unsigned __int8 *)(*(_DWORD *)(result + 12) + 4);
  if ( *(unsigned __int8 *)(result + 64) != v2 )
  {
    v3 = *(int (**)(void))(result + 116);
    *(_BYTE *)(result + 64) = v2;
    result = v3();
    v4 = *(int (__fastcall **)(int))(v1 + 28);
    if ( v4 )
      result = v4(result);
    v5 = *(int (__fastcall **)(_DWORD))(v1 + 32);
    if ( v5 )
      result = v5(*(_DWORD *)(v1 + 36));
  }
  v6 = *(unsigned __int8 *)(*(_DWORD *)(v1 + 12) + 6);
  if ( *(unsigned __int8 *)(v1 + 65) != v6 )
  {
    v7 = *(int (__fastcall **)(_DWORD))(v1 + 40);
    *(_BYTE *)(v1 + 65) = v6;
    if ( v7 )
      result = v7(*(_DWORD *)(v1 + 44));
  }
  v8 = *(unsigned __int8 *)(*(_DWORD *)(v1 + 12) + 7);
  if ( *(unsigned __int8 *)(v1 + 67) != v8 )
  {
    v9 = *(int (__fastcall **)(_DWORD))(v1 + 48);
    *(_BYTE *)(v1 + 67) = v8;
    if ( v9 )
      result = v9(*(_DWORD *)(v1 + 52));
  }
  v10 = *(unsigned __int8 *)(*(_DWORD *)(v1 + 12) + 5);
  if ( *(unsigned __int8 *)(v1 + 66) != v10 )
  {
    v11 = *(int (__fastcall **)(_DWORD))(v1 + 56);
    *(_BYTE *)(v1 + 66) = v10;
    if ( v11 )
      result = v11(*(_DWORD *)(v1 + 60));
    if ( *(_BYTE *)(v1 + 24) )
    {
      if ( v10 )
        return (*(int (__fastcall **)(int))(v1 + 108))(v1);
    }
  }
  return result;
}


// Function: SmdCloseStream
// This function is a simple wrapper function that calls smdi_stream_state_machine to close an SMD stream. It's likely used as a callback or a utility to trigger the closing of a stream.
int __fastcall sub_409900(int *a1)
{
  return smdi_stream_state_machine(a1, 0);
}


// Function: SmdProcessAsyncEvents
// This function is a complex event handler or dispatcher for various SMD-related events and state changes. It reacts to different flags and states within the SMD context, processes signal changes, updates the global stream state machine, and invokes various callbacks. This function seems to be a central point for handling asynchronous notifications or internal state updates within the SMD framework.
int __fastcall sub_40990C(int result)
{
  int v1; // r4
  int v2; // r2
  int v3; // r5
  int v4; // r2
  int v5; // r2

  v1 = result;
  v2 = *(_DWORD *)(result + 64);
  v3 = **(_DWORD **)(result + 60);
  if ( *(_BYTE *)(v2 + 10) )
  {
    *(_BYTE *)(v2 + 10) = 0;
    if ( v3 == 2 || v3 == 3 )
    {
      SmdProcessSignalChanges(result + 52);
      result = SmdGlobalStreamStateMachine(v1 + 52);
    }
    else
    {
      result = SmdGlobalStreamStateMachine(result + 52);
      v3 = **(_DWORD **)(v1 + 60);
      if ( v3 == 2 || v3 == 3 )
        result = SmdProcessSignalChanges(v1 + 52);
    }
  }
  v4 = *(_DWORD *)(v1 + 64);
  if ( *(_BYTE *)(v4 + 9) )
  {
    if ( v3 == 2 || v3 == 3 )
    {
      *(_BYTE *)(v4 + 9) = 0;
      result = (*(int (__fastcall **)(int))(v1 + 160))(v1 + 52);
    }
  }
  else if ( *(_BYTE *)(v1 + 131) && *(_BYTE *)(v1 + 78) )
  {
    result = (*(int (__fastcall **)(int))(v1 + 172))(v1 + 52);
  }
  v5 = *(_DWORD *)(v1 + 64);
  if ( *(_BYTE *)(v5 + 8) && (v3 == 2 || v3 == 3) )
  {
    *(_BYTE *)(v5 + 8) = 0;
    return (*(int (__fastcall **)(int))(v1 + 156))(v1 + 52);
  }
  return result;
}


// Function: SmdCmdHandler
// This function implements the core logic for SMD_CMD_OPEN_SMDLITE and SMD_CMD_LOOPBACK commands. For SMD_CMD_OPEN_SMDLITE, it configures callbacks and potentially calls smdi_stream_state_machine. For SMD_CMD_LOOPBACK, it sets a loopback handler and may enqueue a work item.
int __fastcall sub_4099A8(int result)
{
  ULONG v1; // r4
  int cmd; // r3
  int v3; // r1
  int v4; // r6
  int v5; // r5
  int (__fastcall *v6)(_DWORD); // r2
  int *v7; // r3
  int *v8; // r0
  int v9; // r2

  v1 = result;
  cmd = *(_DWORD *)result;
  if ( *(_DWORD *)result == 1 )                 // SMD_CMD_OPEN_SMDLITE
  {
    v3 = *(_DWORD *)(result + 4);
    v4 = *(unsigned __int8 *)(result + 16);
    v5 = *(_DWORD *)(result + 12);
    v6 = *(int (__fastcall **)(_DWORD))(result + 8);
    if ( v3 == 3 )
    {
      if ( v6 )
        return v6(*(_DWORD *)(result + 12));
    }
    else
    {
      v7 = (int *)smd_port_to_info[v3];
      v8 = v7 + 13;
      v7[34] = (int)v6;
      v7[35] = v5;
      if ( v4 )
      {
        v9 = smd_port_to_info[v3];
        *(_DWORD *)(v9 + 148) = v8;
        *(_DWORD *)(v9 + 144) = SmdCloseStream;
        return (*(int (__fastcall **)(int))(v9 + 164))(v9 + 52);
      }
      else
      {
        return smdi_stream_state_machine(v8, 0);// event SMD_EVENT_CLOSE
      }
    }
  }
  else if ( cmd == 7 )                          // SMD_CMD_LOOPBACK
  {
    *(_DWORD *)(smd_port_to_info[*(_DWORD *)(result + 4)] + 48) = SmdProcessAsyncEvents;
    result = SmdInitializeStreamAndStateMachine();
    if ( *(_BYTE *)(v1 + 8) )
      return ((int (__fastcall *)(int, WDFWORKITEM))WdfFunctions.WdfWorkItemEnqueue)(WdfDriverGlobals, dword_40FBE4);
  }
  else
  {
    return DbgPrintEx(0x4Du, 0, "Unknown cmd %d ignored", cmd);
  }
  return result;
}


// Function: smd_cmd
// https://github.com/Rivko/android-firmware-qti-sdm670/blob/20bb8ae36c93fc16bbadda0e0a83f930c0c8a271/boot_images/QcomPkg/Library/SmdLib/smd_main.c#L1426
void __fastcall smd_cmd(int a1, int a2, int a3, int a4)
{
  unsigned int v5; // r2

  switch ( *(_DWORD *)a1 )                      // https://github.com/Rivko/android-firmware-qti-sdm670/blob/main/boot_images/QcomPkg/Library/SmdLib/smd_main.h#L59
  {
    case 0:                                     // SMD_CMD_OPEN_MEMCPY
    case 1:                                     // SMD_CMD_OPEN_SMDLITE
    case 2:                                     // SMD_CMD_CLOSE
    case 3:                                     // SMD_CMD_FLUSH
    case 7:                                     // SMD_CMD_LOOPBACK
    case 8:                                     // SMD_CMD_PROCESS_PORT
      v5 = *(_DWORD *)(a1 + 4);
      if ( v5 < 0x40 )
        SmdCmdHandlerWithLock(a1, *(_DWORD *)(smd_port_to_info[v5] + 12));
      break;
    case 4:                                     // SMD_CMD_IOCTL
    case 5:                                     // SMD_CMD_REMOTE_RESET
      dword_40FC08 = KeAcquireSpinLockRaiseToDpc(&dword_40FC04);
      SmdCmdHandler(a1);
      KeReleaseSpinLock(&dword_40FC04, dword_40FC08);
      break;
    case 6:                                     // SMD_CMD_REMOTE_RESET_DONE
      SmdCmdHandlerWithLock(a1, &dword_40FBE8);
      break;
    default:
      fatal_error01("Unrecogonized SMD command %d", *(ULONG **)a1, a3, a4);
  }
}


// Function: SmdCmdHandlerWithLock
// This function acts as a wrapper around SmdCmdHandler, providing synchronization using a spinlock. It acquires a spinlock before calling SmdCmdHandler and releases it afterwards.
void __fastcall sub_409B24(int a1, int a2)
{
  *(_BYTE *)(a2 + 32) = KeAcquireSpinLockRaiseToDpc((KSPIN_LOCK *)(a2 + 28));
  SmdCmdHandler(a1);
  KeReleaseSpinLock((KSPIN_LOCK *)(a2 + 28), *(_BYTE *)(a2 + 32));
}


// Function: smd_string_copy
char *__fastcall smd_string_copy(char *dst, char *src, unsigned int size)
{
  unsigned int v6; // r2

  if ( !dst || !src )
    return 0;
  v6 = strlen(src) + 1;
  if ( v6 > size )
  {
    memcpy_forward_new((int)dst, (unsigned int)src, size - 1);
    dst[size - 1] = 0;
  }
  else
  {
    memcpy_forward_new((int)dst, (unsigned int)src, v6);
  }
  return dst;
}


// Function: sub_409BB4
int __fastcall sub_409BB4(int a1, int a2, int a3, int a4, unsigned int a5)
{
  int v5; // r5
  int v6; // r6
  int v9; // r4
  int result; // r0

  v5 = a4;
  v6 = a3;
  if ( a3 + a4 <= a5 )
  {
    v9 = 0;
  }
  else
  {
    v9 = a5 - a4;
    memcpy_forward_new(a1, a2 + a4, a5 - a4);
    v6 -= v9;
    v5 = 0;
  }
  memcpy_forward_new(v9 + a1, a2 + v5, v6);
  result = v6 + v5;
  if ( v6 + v5 == a5 )
    return 0;
  return result;
}


// Function: sub_409C04
int __fastcall sub_409C04(int a1, unsigned int a2, int a3, int a4, unsigned int a5)
{
  int v5; // r5
  int v6; // r6
  int v9; // r4
  int result; // r0

  v5 = a4;
  v6 = a3;
  if ( a3 + a4 <= a5 )
  {
    v9 = 0;
  }
  else
  {
    v9 = a5 - a4;
    memcpy_forward_new(a1 + a4, a2, a5 - a4);
    v6 -= v9;
    v5 = 0;
  }
  memcpy_forward_new(a1 + v5, v9 + a2, v6);
  result = v6 + v5;
  if ( v6 + v5 == a5 )
    return 0;
  return result;
}


// Function: call_device_SMEM
NTSTATUS __fastcall call_device_SMEM(WDFDEVICE Device)
{
  NTSTATUS result; // r0
  int status; // r4
  WDFIOTARGET v3; // r1
  int v4; // r0
  _WDF_MEMORY_DESCRIPTOR v5; // [sp+10h] [bp-B8h] BYREF
  ULONG v6; // [sp+1Ch] [bp-ACh] BYREF
  _WDF_OBJECT_ATTRIBUTES v7; // [sp+20h] [bp-A8h] BYREF
  int v8; // [sp+40h] [bp-88h]
  _WDF_IO_TARGET_OPEN_PARAMS dest; // [sp+48h] [bp-80h] BYREF
  wchar_t v10[16]; // [sp+90h] [bp-38h] BYREF

  wcscpy(v10, L"\\Device\\SMEM");
  v8 = 1703960;
  v7.EvtCleanupCallback = NULL;
  v7.EvtDestroyCallback = NULL;
  v7.ContextSizeOverride = NULL;
  v7.ContextTypeInfo = NULL;
  v7.Size = 32;
  v7.ParentObject = Device;
  v7.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v7.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  result = WdfFunctions.WdfIoTargetCreate(WdfDriverGlobals, Device, &v7, &WDFIOTARGET_SMEM);
  if ( result >= 0 )
  {
    memset(&dest, 0, sizeof(dest));
    dest.Size = 72;
    dest.Type = WdfIoTargetOpenByName;
    *(_DWORD *)&dest.TargetDeviceName.Length = v8;
    dest.DesiredAccess = 2031616;
    dest.CreateOptions = 64;
    dest.CreateDisposition = 1;
    dest.TargetDeviceName.Buffer = v10;
    status = ((int (__fastcall *)(int, WDFIOTARGET, _WDF_IO_TARGET_OPEN_PARAMS *))WdfFunctions.WdfIoTargetOpen)(
               WdfDriverGlobals,
               WDFIOTARGET_SMEM,
               &dest);
    v3 = WDFIOTARGET_SMEM;
    v4 = WdfDriverGlobals;
    if ( status < STATUS_SUCCESS )
    {
DELETE_WDFIOTARGET_SMEM:
      WdfFunctions.WdfObjectDelete(v4, v3);
      WDFIOTARGET_SMEM = 0;
      return status;
    }
    v5.Type = WdfMemoryDescriptorTypeBuffer;
    v5.u.BufferType.Buffer = &SMEM_ioctl42000_outputbuffer_size52;
    v5.u.BufferType.Length = 52;
    status = WdfFunctions.WdfIoTargetSendInternalIoctlSynchronously(
               WdfDriverGlobals,
               WDFIOTARGET_SMEM,
               0,
               0x42000u,
               0,
               &v5,
               0,
               &v6);
    if ( status < STATUS_SUCCESS )
    {
      v3 = WDFIOTARGET_SMEM;
      v4 = WdfDriverGlobals;
      goto DELETE_WDFIOTARGET_SMEM;
    }
    if ( v6 == 52 )
    {
      return STATUS_SUCCESS;
    }
    else
    {
      WdfFunctions.WdfObjectDelete(WdfDriverGlobals, WDFIOTARGET_SMEM);
      WDFIOTARGET_SMEM = 0;
      return STATUS_IO_DEVICE_ERROR;
    }
  }
  return result;
}


// Function: sub_409DA4
int __fastcall sub_409DA4(int a1)
{
  ULONG v2[2]; // [sp+10h] [bp-38h] BYREF
  _DWORD v3[2]; // [sp+18h] [bp-30h] BYREF
  int v4; // [sp+20h] [bp-28h] BYREF
  int v5; // [sp+24h] [bp-24h]
  _WDF_MEMORY_DESCRIPTOR v6; // [sp+28h] [bp-20h] BYREF
  _WDF_MEMORY_DESCRIPTOR v7; // [sp+38h] [bp-10h] BYREF

  v3[0] = 0;
  v3[1] = 0;
  v4 = 0;
  v5 = 0;
  if ( WDFIOTARGET_SMEM
    && (v7.Type = WdfMemoryDescriptorTypeBuffer,
        v7.u.BufferType.Buffer = v3,
        v7.u.BufferType.Length = 8,
        v6.Type = WdfMemoryDescriptorTypeBuffer,
        v6.u.BufferType.Buffer = &v4,
        v6.u.BufferType.Length = 8,
        v3[0] = a1,
        WdfFunctions.WdfIoTargetSendInternalIoctlSynchronously(
          WdfDriverGlobals,
          WDFIOTARGET_SMEM,
          0,
          0x42004u,
          &v7,
          &v6,
          0,
          v2) >= 0) )
  {
    return v5;
  }
  else
  {
    return 0;
  }
}


// Function: EventWrite_04
int EventWrite_04(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5,
        unsigned int a6,
        ...)
{
  char *v6; // r4
  unsigned int v7; // r5
  unsigned int v8; // r6
  size_t v9; // r3
  char *v10; // r4
  size_t v11; // r3
  unsigned int var40[21]; // [sp+8h] [bp-50h] BYREF
  va_list va; // [sp+7Ch] [bp+24h] BYREF

  va_start(va, a6);
  v6 = a4;
  v7 = HIDWORD(RegHandle);
  v8 = RegHandle;
  if ( a4 )
  {
    v9 = strlen(a4) + 1;
  }
  else
  {
    v6 = "NULL";
    v9 = 5;
  }
  var40[0] = (unsigned int)v6;
  v10 = a5;
  var40[2] = v9;
  var40[1] = 0;
  var40[3] = 0;
  if ( a5 )
  {
    v11 = strlen(a5) + 1;
  }
  else
  {
    v10 = "NULL";
    v11 = 5;
  }
  var40[6] = v11;
  var40[7] = 0;
  var40[4] = (unsigned int)v10;
  var40[8] = a6;
  var40[9] = 0;
  var40[10] = 16;
  var40[11] = 0;
  va_copy((va_list)&var40[12], va);
  var40[13] = 0;
  var40[14] = 4;
  var40[15] = 0;
  var40[5] = 0;
  return EtwWrite(__PAIR64__(v7, v8), &stru_40E378, 0, 4u, var40);
}


// Function: EventWrite_05
int __fastcall EventWrite_05(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4)
{
  char *v4; // r4
  unsigned int v6; // r6
  unsigned int v7; // r7
  size_t v8; // r3
  unsigned int v10[5]; // [sp+8h] [bp-28h] BYREF

  v4 = a4;
  v6 = HIDWORD(RegHandle);
  v7 = RegHandle;
  if ( a4 )
  {
    v8 = strlen(a4) + 1;
  }
  else
  {
    v4 = "NULL";
    v8 = 5;
  }
  v10[2] = v8;
  v10[3] = 0;
  v10[0] = (unsigned int)v4;
  v10[1] = 0;
  return EtwWrite(__PAIR64__(v6, v7), EventDescriptor, 0, 1u, v10);
}


// Function: EventWrite_06
int EventWrite_06(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5,
        ...)
{
  char *v5; // r4
  unsigned int v6; // r5
  unsigned int v7; // r6
  size_t v8; // r3
  char *v9; // r4
  size_t v10; // r3
  unsigned int var50[25]; // [sp+8h] [bp-60h] BYREF
  int v13; // [sp+88h] [bp+20h] BYREF
  int v14; // [sp+8Ch] [bp+24h]
  void *v15; // [sp+90h] [bp+28h] BYREF
  int v16; // [sp+94h] [bp+2Ch]
  va_list va2; // [sp+98h] [bp+30h] BYREF
  va_list va; // [sp+88h] [bp+20h]
  va_list va1; // [sp+90h] [bp+28h]

  va_start(va2, a5);
  va_start(va1, a5);
  va_start(va, a5);
  v13 = va_arg(va1, _DWORD);
  v14 = va_arg(va1, _DWORD);
  va_copy(va2, va1);
  v15 = va_arg(va2, void *);
  v16 = va_arg(va2, _DWORD);
  v5 = a4;
  v6 = HIDWORD(RegHandle);
  v7 = RegHandle;
  if ( a4 )
  {
    v8 = strlen(a4) + 1;
  }
  else
  {
    v5 = "NULL";
    v8 = 5;
  }
  var50[0] = (unsigned int)v5;
  v9 = a5;
  var50[2] = v8;
  var50[1] = 0;
  var50[3] = 0;
  if ( a5 )
  {
    v10 = strlen(a5) + 1;
  }
  else
  {
    v9 = "NULL";
    v10 = 5;
  }
  var50[6] = v10;
  var50[7] = 0;
  va_copy((va_list)&var50[8], va);
  var50[9] = 0;
  var50[10] = 8;
  var50[11] = 0;
  va_copy((va_list)&var50[12], va1);
  var50[13] = 0;
  var50[14] = 4;
  var50[15] = 0;
  va_copy((va_list)&var50[16], va2);
  var50[17] = 0;
  var50[18] = 8;
  var50[19] = 0;
  var50[4] = (unsigned int)v9;
  var50[5] = 0;
  return EtwWrite(__PAIR64__(v6, v7), &stru_40E338, 0, 5u, var50);
}


// Function: EventWrite_07
int __fastcall EventWrite_07(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        char *a4,
        char *a5,
        unsigned int a6)
{
  char *v6; // r4
  unsigned int v8; // r6
  unsigned int v9; // r7
  size_t v10; // r3
  char *v11; // r4
  size_t v12; // r3
  unsigned int v14[13]; // [sp+8h] [bp-48h] BYREF

  v6 = a4;
  v8 = HIDWORD(RegHandle);
  v9 = RegHandle;
  if ( a4 )
  {
    v10 = strlen(a4) + 1;
  }
  else
  {
    v6 = "NULL";
    v10 = 5;
  }
  v14[0] = (unsigned int)v6;
  v11 = a5;
  v14[2] = v10;
  v14[1] = 0;
  v14[3] = 0;
  if ( a5 )
  {
    v12 = strlen(a5) + 1;
  }
  else
  {
    v11 = "NULL";
    v12 = 5;
  }
  v14[6] = v12;
  v14[7] = 0;
  v14[4] = (unsigned int)v11;
  v14[8] = a6;
  v14[9] = 0;
  v14[10] = 16;
  v14[11] = 0;
  v14[5] = 0;
  return EtwWrite(__PAIR64__(v8, v9), EventDescriptor, 0, 3u, v14);
}


// Function: EventWrite_08
int EventWrite_08(
        unsigned __int64 RegHandle,
        const _EVENT_DESCRIPTOR *EventDescriptor,
        const _GUID *ActivityId,
        int a4,
        ...)
{
  unsigned int var20[13]; // [sp+8h] [bp-30h] BYREF
  va_list va; // [sp+54h] [bp+1Ch] BYREF

  va_start(va, a4);
  var20[2] = strlen("_openRpenIoTarget") + 1;
  var20[3] = 0;
  va_copy((va_list)&var20[4], va);
  var20[5] = 0;
  var20[6] = 4;
  var20[7] = 0;
  var20[0] = (unsigned int)"_openRpenIoTarget";
  var20[1] = 0;
  return EtwWrite(RegHandle, &stru_40E358, 0, 2u, var20);
}


// Function: RpeClientInit
int __fastcall RpeClientInit(_DWORD *a1, int a2, int a3, _DWORD *a4, int a5, int a6, int a7, int a8, int a9)
{
  _DWORD var10[16]; // [sp+10h] [bp-28h] BYREF

  var10[12] = a1;
  var10[13] = a2;
  var10[14] = a3;
  var10[15] = a4;
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)&ETW_RegistrationHandle_01, "RpeClientInit");
  }
  if ( !a8 && !a7 )
    return RpeClientInitMultiSegment(a1, a2, a3, a4, 0, 0, a9);
  var10[2] = a7;
  var10[3] = a8;
  var10[0] = a5;
  var10[1] = a6;
  return RpeClientInitMultiSegment(a1, a2, a3, a4, (unsigned int)var10, 1, a9);
}


// Function: RpeClientInitMultiSegment
NT_STATUS_VALUES __fastcall RpeClientInitMultiSegment(
        _DWORD *a1,
        int a2,
        int a3,
        _DWORD *a4,
        unsigned int a5,
        unsigned __int8 a6,
        int a7)
{
  _DWORD *v7; // r4
  int v9; // lr
  _DWORD *v10; // r2
  int v11; // r7
  NT_STATUS_VALUES v13; // r4
  RPE_CLIENT_CONTEXT *v14; // r0
  RPE_CLIENT_CONTEXT *v15; // r7
  _DWORD *v17; // r2
  int v18; // r1
  int v19; // r3
  int v20; // r2
  char *v21; // r3
  int v22; // r0
  int v23; // r1
  char *v24; // r3
  int v25; // r2
  int v26; // r0
  _DWORD *v27; // r2
  PVOID PoolWithTag; // r0
  PVOID v29; // r3
  const _EVENT_DESCRIPTOR *v31; // r2
  void *v33; // [sp+10h] [bp-58h] BYREF
  _DWORD *v34; // [sp+14h] [bp-54h]
  int v35; // [sp+18h] [bp-50h]
  _DWORD *v36; // [sp+1Ch] [bp-4Ch]
  PVOID v37; // [sp+20h] [bp-48h]
  int v38; // [sp+24h] [bp-44h]
  _WDF_OBJECT_ATTRIBUTES v39; // [sp+28h] [bp-40h] BYREF

  v7 = a4;
  v9 = dword_415994;
  v38 = a3;
  v10 = a1;
  v11 = (unsigned __int8)byte_415998;
  v34 = a4;
  v35 = a2;
  v36 = a1;
  v37 = 0;
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
    {
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, 0, "RpeClientInitMultiSegment");
      v9 = dword_415994;
      v11 = (unsigned __int8)byte_415998;
      v10 = v36;
      a2 = v35;
    }
    v7 = v34;
  }
  if ( !byte_415961 )
  {
    v13 = -536182524;
    if ( v9 )
    {
      if ( v11 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E3B8,
          (const _GUID *)"RPE not initialized! Call RpeInit() first!",
          "RpeClientInitMultiSegment",
          "RPE not initialized! Call RpeInit() first!",
          -536182524);
    }
    return v13;
  }
  if ( !v10 || !a2 || !a3 || !v7 || !v7[1] )
  {
    v13 = STATUS_INVALID_PARAMETER;
    if ( v9 && v11 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client information is NULL!",
        "RpeClientInitMultiSegment",
        "Client information is NULL!",
        STATUS_INVALID_PARAMETER);
    return v13;
  }
  v39.EvtCleanupCallback = 0;
  v39.EvtDestroyCallback = 0;
  v39.ParentObject = 0;
  v39.ContextSizeOverride = 0;
  v39.Size = 32;
  v39.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v39.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v39.ContextTypeInfo = (_WDF_OBJECT_CONTEXT_TYPE_INFO *)WDF_RPE_CLIENT_CONTEXT_TYPE_INFO.UniqueType;
  v13 = WdfFunctions.WdfObjectCreate(WdfDriverGlobals, &v39, &v33);
  if ( v13 < STATUS_SUCCESS )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfObjectCreate",
        "RpeClientInitMultiSegment",
        "WdfObjectCreate",
        v13);
    return v13;
  }
  v14 = (RPE_CLIENT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                WdfDriverGlobals,
                                v33,
                                WDF_RPE_CLIENT_CONTEXT_TYPE_INFO.UniqueType);
  v15 = v14;
  if ( !v14 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_03(
        ETW_RegistrationHandle_01,
        &stru_40E388,
        (const _GUID *)"Client context",
        "RpeClientInitMultiSegment",
        "Client context",
        v33,
        STATUS_IO_DEVICE_ERROR);
    WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v33);
    return STATUS_IO_DEVICE_ERROR;
  }
  v17 = v36;
  v18 = v35;
  *(_DWORD *)&v14->field_0 = *v36;
  *(_DWORD *)&v14->? = v17[1];
  *(_DWORD *)&v14->? = v17[2];
  v19 = v17[3];
  v20 = 64;
  *(_DWORD *)&v14->? = v19;
  v21 = &v14->field_14;
  v22 = v18 - (_DWORD)&v14->field_14;
  while ( v21[v22] )
  {
    *v21 = v21[v22];
    ++v21;
    if ( !--v20 )
    {
      --v21;
      break;
    }
  }
  v23 = v38;
  *v21 = 0;
  v24 = &v15->field_54;
  v25 = 128;
  v26 = v23 - (_DWORD)&v15->field_54;
  while ( v24[v26] )
  {
    *v24 = v24[v26];
    ++v24;
    if ( !--v25 )
    {
      --v24;
      break;
    }
  }
  v27 = v34;
  *v24 = 0;
  *(_DWORD *)&v15->field_d4 = *v27;
  *(_DWORD *)&v15->field_d8 = v27[1];
  *(_DWORD *)&v15->field_dc = v27[2];
  *(_DWORD *)&v15->field_e0 = v27[3];
  if ( a6 && a5 )
  {
    PoolWithTag = ExAllocatePoolWithTag(PagedPool, 16 * a6, 'qrha');
    v37 = PoolWithTag;
    if ( !PoolWithTag )
    {
      if ( dword_415994 && byte_415998 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E3B8,
          (const _GUID *)"ExAllocatePoolWithTag failed!",
          "RpeClientInitMultiSegment",
          "ExAllocatePoolWithTag failed!",
          STATUS_NO_MEMORY);
      WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v33);
      return STATUS_NO_MEMORY;
    }
    memcpy_forward_new((int)PoolWithTag, a5, 16 * a6);
    v29 = v37;
    v15->field_e8 = a6;
    *(_DWORD *)&v15->field_e4 = v29;
  }
  else
  {
    *(_DWORD *)&v15->field_e4 = 0;
    v15->field_e8 = 0;
  }
  v15->field_f8 = 0;
  v15->field_f9 = 0;
  *(_DWORD *)&v15->field_ec = a7;
  v15->field_fb = 1;
  v15->field_fa = 0;
  *(_DWORD *)&v15->field_10 = 0;
  v39.EvtCleanupCallback = 0;
  v39.EvtDestroyCallback = 0;
  v39.ContextSizeOverride = 0;
  v39.ContextTypeInfo = 0;
  v39.Size = 32;
  v39.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v39.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v39.ParentObject = v33;
  v13 = WdfFunctions.WdfCollectionCreate(WdfDriverGlobals, &v39, &v15->field_f0);
  if ( v13 < STATUS_SUCCESS )
    goto LABEL_46;
  v39.EvtCleanupCallback = 0;
  v39.EvtDestroyCallback = 0;
  v39.ContextSizeOverride = 0;
  v39.ContextTypeInfo = 0;
  v39.Size = 32;
  v39.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v39.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v39.ParentObject = v33;
  v13 = WdfFunctions.WdfCollectionCreate(WdfDriverGlobals, &v39, &v15->field_f4);
  if ( v13 < STATUS_SUCCESS )
  {
LABEL_46:
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfCollectionCreate",
        "RpeClientInitMultiSegment",
        "WdfCollectionCreate",
        v13);
    goto LABEL_48;
  }
  v13 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, dword_4159F0, 0);
  if ( v13 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfWaitLockAcquire",
        "RpeClientInitMultiSegment",
        "WdfWaitLockAcquire",
        v13);
LABEL_48:
    WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v33);
    goto LABEL_74;
  }
  v13 = WdfFunctions.WdfCollectionAdd(WdfDriverGlobals, Collection_RPEClients, v33);
  if ( v13 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfCollectionAdd",
        "RpeClientInitMultiSegment",
        "WdfCollectionAdd",
        v13);
    WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v33);
LABEL_73:
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
LABEL_74:
    if ( v37 )
    {
      ExFreePoolWithTag(v37, 'qrha');
      return v13;
    }
    return v13;
  }
  if ( byte_415962 == 1 )
  {
    if ( dword_415994 )
    {
      if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
        EventWrite_07(
          ETW_RegistrationHandle_01,
          &stru_40E3A8,
          (const _GUID *)"Client init information",
          "RpeClientInitMultiSegment",
          "Client init information",
          (unsigned int)v15);
    }
    v13 = off_4159D0(v36, v35, v38, v34, *(_DWORD *)&v15->field_e4, (unsigned __int8)v15->field_e8, a7);
    if ( v13 )
    {
      if ( dword_415994 && byte_415998 != 1 )
        EventWrite_04(
          ETW_RegistrationHandle_01,
          v31,
          (const _GUID *)"client init information",
          "RpeClientInitMultiSegment",
          "client init information",
          (unsigned int)v15,
          v13);
      WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, Collection_RPEClients, v33);
      WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v33);
    }
    else
    {
      v15->field_f8 = 1;
    }
    goto LABEL_73;
  }
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 3u || !byte_415998 )
      EventWrite_07(
        ETW_RegistrationHandle_01,
        &stru_40E328,
        (const _GUID *)"Client init information",
        "RpeClientInitMultiSegment",
        "Client init information",
        (unsigned int)v15);
  }
  v15->field_f8 = 0;
  WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
  return -536182528;
}


// Function: RpeSendState
int __fastcall RpeSendState(int a1)
{
  int v1; // r3
  int v2; // r1
  int v3; // r2
  int v5; // r5
  NTSTATUS v6; // r0
  RPE_CLIENT_CONTEXT *ClientContextByGUID; // r0
  unsigned int v8; // r7
  int v9; // r5
  const _EVENT_DESCRIPTOR *v11; // r2
  char v12; // r3
  int v15; // [sp+10h] [bp-20h] BYREF

  v1 = 0;
  v2 = dword_415994;
  v3 = (unsigned __int8)byte_415998;
  v15 = 0;
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
      v1 = 1;
    if ( v1 )
    {
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)v1, "RpeSendState");
      v3 = (unsigned __int8)byte_415998;
      v2 = dword_415994;
    }
  }
  if ( !byte_415961 )
  {
    v5 = -536182524;
    if ( v2 )
    {
      if ( v3 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E3B8,
          (const _GUID *)"RPE not initialized! Call RpeInit() first!",
          "RpeSendState",
          "RPE not initialized! Call RpeInit() first!",
          -536182524);
    }
    return v5;
  }
  if ( !a1 )
  {
    v5 = STATUS_INVALID_PARAMETER;
    if ( v2 && v3 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client state information is NULL!",
        "RpeSendState",
        "Client state information is NULL!",
        STATUS_INVALID_PARAMETER);
    return v5;
  }
  if ( *(_DWORD *)(a1 + 20) >= 8u )
  {
    v5 = STATUS_INVALID_PARAMETER;
    if ( v2 && v3 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client state information is invalid!",
        "RpeSendState",
        "Client state information is invalid!",
        STATUS_INVALID_PARAMETER);
    return v5;
  }
  v6 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, dword_4159F0, 0);
  v5 = v6;
  if ( v6 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfWaitLockAcquire",
        "RpeSendState",
        "WdfWaitLockAcquire",
        v6);
    return v5;
  }
  ClientContextByGUID = getClientContextByGUID((GUID *)(a1 + 4), &v15);
  v8 = (unsigned int)ClientContextByGUID;
  if ( ClientContextByGUID )
  {
    *(_DWORD *)&ClientContextByGUID->field_10 = *(_DWORD *)(a1 + 20);
    if ( byte_415962 == 1 )
    {
      if ( dword_415994 )
      {
        if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
          EventWrite_07(
            ETW_RegistrationHandle_01,
            &stru_40E3A8,
            (const _GUID *)"Client state information",
            "RpeSendState",
            "Client state information",
            (unsigned int)ClientContextByGUID);
      }
      v9 = off_4159D8(a1);
      if ( v9 < 0 && dword_415994 && byte_415998 != 1 )
        EventWrite_04(
          ETW_RegistrationHandle_01,
          v11,
          (const _GUID *)"client state information",
          "RpeSendState",
          "client state information",
          v8,
          v9,
          v15);
      v12 = 1;
    }
    else
    {
      if ( dword_415994 )
      {
        if ( (unsigned __int8)byte_415998 >= 3u || !byte_415998 )
          EventWrite_07(
            ETW_RegistrationHandle_01,
            &stru_40E328,
            (const _GUID *)"Client state information",
            "RpeSendState",
            "Client state information",
            (unsigned int)ClientContextByGUID);
      }
      v9 = -536182528;
      v12 = 0;
    }
    *(_BYTE *)(v8 + 249) = v12;
  }
  else
  {
    v9 = -536182527;
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client not found! Did you call RpeClientInit()?",
        "RpeSendState",
        "Client not found! Did you call RpeClientInit()?",
        -536182527);
  }
  WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
  return v9;
}


// Function: RpeRegisterForStateNotification
NT_STATUS_VALUES __fastcall RpeRegisterForStateNotification(GUID *a1, _DWORD *a2)
{
  int v3; // r3
  int v4; // r9
  int v5; // r7
  NT_STATUS_VALUES v7; // r6
  NTSTATUS v8; // r0
  RPE_CLIENT_CONTEXT *ClientContextByGUID; // r10
  int v10; // r6
  RPE_CLIENT_NOTIFICATION *v12; // r1
  GUID *v13; // r2
  int v14; // r0
  int v15; // r3
  _DWORD *v16; // r2
  const _EVENT_DESCRIPTOR *v18; // r2
  char v19; // r2
  void *v21; // [sp+10h] [bp-50h] BYREF
  RPE_CLIENT_NOTIFICATION *v22; // [sp+14h] [bp-4Ch] BYREF
  _DWORD *v23; // [sp+18h] [bp-48h]
  GUID *v24; // [sp+1Ch] [bp-44h]
  _WDF_OBJECT_ATTRIBUTES v25; // [sp+20h] [bp-40h] BYREF

  v3 = 0;
  v4 = dword_415994;
  v5 = (unsigned __int8)byte_415998;
  v23 = a2;
  v24 = a1;
  v22 = 0;
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
      v3 = 1;
    if ( v3 )
    {
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)v3, "RpeRegisterForStateNotification");
      v5 = (unsigned __int8)byte_415998;
      v4 = dword_415994;
    }
  }
  if ( !byte_415961 )
  {
    v7 = -536182524;
    if ( v4 )
    {
      if ( v5 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E3B8,
          (const _GUID *)"RPE not initialized! Call RpeInit() first!",
          "RpeRegisterForStateNotification",
          "RPE not initialized! Call RpeInit() first!",
          -536182524);
    }
    return v7;
  }
  if ( !a1 || !a2 || !SmdModemStateNotificationCallback )
  {
    v7 = STATUS_INVALID_PARAMETER;
    if ( v4 && v5 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client information is NULL!",
        "RpeRegisterForStateNotification",
        "Client information is NULL!",
        STATUS_INVALID_PARAMETER);
    return v7;
  }
  if ( a2[5] >= 8u )
  {
    v7 = STATUS_INVALID_PARAMETER;
    if ( v4 && v5 != 1 )
    {
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"RpeSendState",
        "RpeSendState",
        "Client state information is invalid!",
        STATUS_INVALID_PARAMETER);
      return STATUS_INVALID_PARAMETER;
    }
    return v7;
  }
  if ( !memcmp(a2 + 1, a1, 0x10u) )
  {
    v7 = STATUS_INVALID_PARAMETER;
    if ( v4 && v5 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"A client cannot register for itself!",
        "RpeRegisterForStateNotification",
        "A client cannot register for itself!",
        STATUS_INVALID_PARAMETER);
    return v7;
  }
  v8 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, dword_4159F0, 0);
  v7 = v8;
  if ( v8 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfWaitLockAcquire",
        "RpeRegisterForStateNotification",
        "WdfWaitLockAcquire",
        v8);
    return v7;
  }
  ClientContextByGUID = getClientContextByGUID(a1, &v22);
  if ( !ClientContextByGUID )
  {
    v10 = -536182527;
    if ( dword_415994 && byte_415998 != 1 )
    {
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"Client not found! Did you call RpeClientInit()?",
        "RpeRegisterForStateNotification",
        "Client not found! Did you call RpeClientInit()?",
        -536182527);
      WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
      return STATUS_CTX_WINSTATION_NAME_INVALID|0x20008100;
    }
    goto LABEL_64;
  }
  v25.EvtCleanupCallback = 0;
  v25.EvtDestroyCallback = 0;
  v25.ContextSizeOverride = 0;
  v25.Size = 32;
  v25.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  v25.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  v25.ContextTypeInfo = (_WDF_OBJECT_CONTEXT_TYPE_INFO *)WDF_RPE_CLIENT_NOTIFICATION_TYPE_INFO.UniqueType;
  v25.ParentObject = v22;
  v10 = WdfFunctions.WdfObjectCreate(WdfDriverGlobals, &v25, &v21);
  if ( v10 < 0 )
  {
    if ( dword_415994 && byte_415998 != 1 )
    {
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfObjectCreate",
        "RpeRegisterForStateNotification",
        "WdfObjectCreate",
        v10);
      WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
      return v10;
    }
    goto LABEL_64;
  }
  v12 = (RPE_CLIENT_NOTIFICATION *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                     WdfDriverGlobals,
                                     v21,
                                     WDF_RPE_CLIENT_NOTIFICATION_TYPE_INFO.UniqueType);
  v22 = v12;
  if ( !v12 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_03(
        ETW_RegistrationHandle_01,
        &stru_40E388,
        (const _GUID *)"Client context",
        "RpeRegisterForStateNotification",
        "Client context",
        v21,
        v10);
LABEL_35:
    WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v21);
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
    return v10;
  }
  v13 = v24;
  v14 = WdfDriverGlobals;
  *(_DWORD *)&v12->field_0 = v24->Data1;
  *(_DWORD *)&v12->field_4 = *(_DWORD *)&v13->Data2;
  *(_DWORD *)&v12->field_8 = *(_DWORD *)v13->Data4;
  v15 = *(_DWORD *)&v13->Data4[4];
  v16 = v23;
  *(_DWORD *)&v12->field_c = v15;
  *(_DWORD *)&v12->field_10 = *v16;
  *(_DWORD *)&v12->field_14 = v16[1];
  *(_DWORD *)&v12->field_18 = v16[2];
  *(_DWORD *)&v12->field_1c = v16[3];
  *(_DWORD *)&v12->field_20 = v16[4];
  *(_DWORD *)&v12->field_24 = v16[5];
  *(_DWORD *)&v12->field_28 = SmdModemStateNotificationCallback;
  v12->field_2c = 0;
  v12->field_2d = 0;
  v12->field_2e = 1;
  v10 = WdfFunctions.WdfCollectionAdd(v14, ClientContextByGUID->field_f0, v21);
  if ( v10 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfCollectionAdd",
        "RpeRegisterForStateNotification",
        "WdfCollectionAdd",
        v10);
    goto LABEL_35;
  }
  if ( byte_415962 != 1 )
  {
    if ( dword_415994 )
    {
      if ( (unsigned __int8)byte_415998 >= 3u || !byte_415998 )
        EventWrite_07(
          ETW_RegistrationHandle_01,
          &stru_40E328,
          (const _GUID *)"Client state registration information",
          "RpeRegisterForStateNotification",
          "Client state registration information",
          (unsigned int)ClientContextByGUID);
    }
    v10 = -536182528;
    v19 = 0;
    goto LABEL_63;
  }
  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
      EventWrite_07(
        ETW_RegistrationHandle_01,
        &stru_40E3A8,
        (const _GUID *)"Client state registration information",
        "RpeRegisterForStateNotification",
        "Client state registration information",
        (unsigned int)ClientContextByGUID);
  }
  v10 = off_4159E0(v24, v23, SmdModemStateNotificationCallback);
  if ( v10 >= 0 )
  {
    v19 = 1;
LABEL_63:
    v22->field_2c = v19;
LABEL_64:
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
    return v10;
  }
  if ( dword_415994 && byte_415998 != 1 )
    EventWrite_04(
      ETW_RegistrationHandle_01,
      v18,
      (const _GUID *)"client state registration information",
      "RpeRegisterForStateNotification",
      "client state registration information",
      (unsigned int)ClientContextByGUID,
      v10);
  WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, ClientContextByGUID->field_f0, v21);
  WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v21);
  WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
  return v10;
}


// Function: RPEHelperEvtNotifyInterfaceChange
int __fastcall RPEHelperEvtNotifyInterfaceChange(int a1)
{
  BOOL v2; // r3
  NTSTATUS v3; // r0
  void *v5; // r10
  int v7; // r0
  void *v9; // [sp+10h] [bp-58h] BYREF
  _WDF_WORKITEM_CONFIG v10; // [sp+18h] [bp-50h] BYREF
  _WDF_OBJECT_ATTRIBUTES v11; // [sp+28h] [bp-40h] BYREF

  if ( dword_415994 )
  {
    v2 = (unsigned __int8)byte_415998 >= 5u || !byte_415998;
    if ( v2 )
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)v2, "RPEHelperEvtNotifyInterfaceChange");
  }
  v3 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, dword_4159F0, 0);
  if ( v3 )
  {
    if ( dword_415994 )
    {
      if ( byte_415998 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E348,
          (const _GUID *)"WdfWaitLockAcquire",
          "RPEHelperEvtNotifyInterfaceChange",
          "WdfWaitLockAcquire",
          v3);
    }
    return 0;
  }
  else
  {
    v5 = (void *)dword_4159EC;
    if ( dword_4159EC )
    {
      if ( !memcmp((const void *)(a1 + 20), &unk_40E208, 0x10u) )
      {
        if ( !memcmp((const void *)(a1 + 4), &GUID_DEVICE_INTERFACE_ARRIVAL, 0x10u) )
        {
          if ( dword_415994 )
          {
            if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
            {
              EventWrite_01(
                ETW_RegistrationHandle_01,
                &stru_40E2D8,
                (const _GUID *)"Arrival",
                "RPEHelperEvtNotifyInterfaceChange",
                "Arrival");
              v5 = (void *)dword_4159EC;
            }
          }
          *(_DWORD *)&v10.AutomaticSerialization = 1;
          v10.Size = 12;
          v10.EvtWorkItemFunc = sub_40B23C;
          v11.EvtCleanupCallback = 0;
          v11.EvtDestroyCallback = 0;
          v11.ContextSizeOverride = 0;
          v11.ContextTypeInfo = 0;
          v11.Size = 32;
          v11.ExecutionLevel = WdfExecutionLevelInheritFromParent;
          v11.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
          v11.ParentObject = v5;
          v7 = WdfFunctions.WdfWorkItemCreate(WdfDriverGlobals, &v10, &v11, &v9);
          if ( v7 >= 0 )
          {
            WdfFunctions.WdfWorkItemEnqueue(WdfDriverGlobals, v9);
          }
          else if ( dword_415994 && byte_415998 != 1 )
          {
            EventWrite_02(
              ETW_RegistrationHandle_01,
              &stru_40E348,
              (const _GUID *)"WdfWorkItemCreate",
              "RPEHelperEvtNotifyInterfaceChange",
              "WdfWorkItemCreate",
              v7);
          }
        }
        else
        {
          if ( dword_415994 )
          {
            if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
              EventWrite_01(
                ETW_RegistrationHandle_01,
                &stru_40E2D8,
                (const _GUID *)"Removal",
                "RPEHelperEvtNotifyInterfaceChange",
                "Removal");
          }
          if ( byte_415962 == 1 )
          {
            byte_415962 = 0;
            WdfFunctions.WdfIoTargetClose(WdfDriverGlobals, (WDFIOTARGET)dword_4159F8);
            WdfFunctions.WdfObjectDelete(WdfDriverGlobals, (WDFOBJECT)dword_4159F8);
          }
        }
      }
      else if ( dword_415994 && byte_415998 != 1 )
      {
        EventWrite_05(
          ETW_RegistrationHandle_01,
          &stru_40E398,
          (const _GUID *)(byte_415998 != 1),
          "RPEHelperEvtNotifyInterfaceChange");
      }
    }
    else if ( dword_415994 && byte_415998 != 1 )
    {
      EventWrite_05(
        ETW_RegistrationHandle_01,
        &stru_40E318,
        (const _GUID *)(byte_415998 != 1),
        "RPEHelperEvtNotifyInterfaceChange");
    }
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, dword_4159F0);
    return 0;
  }
}


// Function: sub_40B23C
void __fastcall sub_40B23C(WDFWORKITEM *a1)
{
  openRpenIoTarget();
  WdfFunctions.WdfObjectDelete(WdfDriverGlobals, a1);
}


// Function: SendRPEClientStatusToNotifier
RPE_COMMAND_NOTIFICATION *SendRPEClientStatusToNotifier()
{
  int v0; // r4
  BOOL v1; // r3
  RPE_COMMAND_NOTIFICATION *result; // r0
  RPE_COMMAND_NOTIFICATION *v3; // r5
  RPE_COMMAND_NOTIFICATION *v4; // r9
  const _EVENT_DESCRIPTOR *v6; // r2
  void *v7; // r0
  int v8; // r6
  ULONG v9; // r8
  void *v10; // r0
  void *v11; // r5
  RPE_CLIENT_NOTIFICATION *v12; // r0
  RPE_CLIENT_NOTIFICATION *v13; // r4
  int v14; // r0
  int v15; // r3
  const _EVENT_DESCRIPTOR *v18; // r2
  const _EVENT_DESCRIPTOR *v20; // r2
  const _EVENT_DESCRIPTOR *v21; // r2
  RPE_COMMAND_NOTIFICATION *v22; // r6
  unsigned int v23; // r5
  RPE_COMMAND_NOTIFICATION *v24; // r4
  const _EVENT_DESCRIPTOR *v25; // r2
  const _EVENT_DESCRIPTOR *v27; // r2
  int v28; // [sp+14h] [bp-54h]
  int v29; // [sp+20h] [bp-48h]
  _EVENT_DESCRIPTOR *EventDescriptor; // [sp+24h] [bp-44h]
  RPE_COMMAND_NOTIFICATION *v31; // [sp+28h] [bp-40h]
  int v32; // [sp+30h] [bp-38h] BYREF
  int v33; // [sp+34h] [bp-34h]
  int v34; // [sp+38h] [bp-30h]
  int v35; // [sp+3Ch] [bp-2Ch]
  int v36; // [sp+40h] [bp-28h]
  int v37; // [sp+44h] [bp-24h]

  v0 = 0;
  v29 = 0;
  if ( dword_415994 )
  {
    v1 = (unsigned __int8)byte_415998 >= 5u || !byte_415998;
    if ( v1 )
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)v1, "SendRPEClientStatusToNotifier");
  }
  result = (RPE_COMMAND_NOTIFICATION *)WdfFunctions.WdfCollectionGetCount(
                                         WdfDriverGlobals,
                                         (WDFCOLLECTION)Collection_RPEClients);
  EventDescriptor = 0;
  v31 = result;
  if ( result )
  {
    do
    {
      result = (RPE_COMMAND_NOTIFICATION *)((int (__fastcall *)(int, int))WdfFunctions.WdfCollectionGetItem)(
                                             WdfDriverGlobals,
                                             Collection_RPEClients);
      v3 = result;
      if ( result )
      {
        result = (RPE_COMMAND_NOTIFICATION *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                               WdfDriverGlobals,
                                               result,
                                               WDF_RPE_CLIENT_CONTEXT_TYPE_INFO.UniqueType);
        v4 = result;
        if ( result )
        {
          if ( result[5].field_1f != 1 )
          {
            if ( !result[5].field_1c && !result[5].field_1e )
            {
              WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, (WDFCOLLECTION)Collection_RPEClients, v3);
              result = (RPE_COMMAND_NOTIFICATION *)((int (__fastcall *)(int, RPE_COMMAND_NOTIFICATION *))WdfFunctions.WdfObjectDelete)(
                                                     WdfDriverGlobals,
                                                     v3);
            }
            if ( v4[5].field_1c == 1 && !v4[5].field_1e )
            {
              if ( dword_415994 )
              {
                if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                  EventWrite_07(
                    ETW_RegistrationHandle_01,
                    &stru_40E3A8,
                    (const _GUID *)"Client deinit information",
                    "SendRPEClientStatusToNotifier",
                    "Client deinit information",
                    (unsigned int)v4);
              }
              off_4159D4(v4);
              if ( v0 && dword_415994 && byte_415998 != 1 )
                EventWrite_04(
                  ETW_RegistrationHandle_01,
                  v27,
                  (const _GUID *)"client deinit information",
                  "SendRPEClientStatusToNotifier",
                  "client deinit information",
                  (unsigned int)v4,
                  v0);
              WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, (WDFCOLLECTION)Collection_RPEClients, v3);
              result = (RPE_COMMAND_NOTIFICATION *)((int (__fastcall *)(int, RPE_COMMAND_NOTIFICATION *))WdfFunctions.WdfObjectDelete)(
                                                     WdfDriverGlobals,
                                                     v3);
            }
            goto LABEL_106;
          }
          if ( !result[5].field_1c )
          {
            if ( dword_415994 )
            {
              if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                EventWrite_07(
                  ETW_RegistrationHandle_01,
                  &stru_40E3A8,
                  (const _GUID *)"Client init information",
                  "SendRPEClientStatusToNotifier",
                  "Client init information",
                  (unsigned int)result);
            }
            v0 = off_4159D0(
                   v4,
                   &v4->field_14,
                   &v4[1].field_28,
                   &v4[4].field_24,
                   *(_DWORD *)&v4[5].field_8,
                   (unsigned __int8)v4[5].field_c,
                   *(_DWORD *)&v4[5].field_10);
            v29 = v0;
            if ( v0 )
            {
              if ( dword_415994 && byte_415998 != 1 )
                EventWrite_04(
                  ETW_RegistrationHandle_01,
                  v6,
                  (const _GUID *)"client init information",
                  "SendRPEClientStatusToNotifier",
                  "client init information",
                  (unsigned int)v4,
                  v0);
              WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, (WDFCOLLECTION)Collection_RPEClients, v3);
            }
            else
            {
              v4[5].field_1c = 1;
            }
            v7 = *(void **)&v4[5].field_8;
            if ( v7 )
              ExFreePoolWithTag(v7, 0x71726861u);
          }
          v8 = 0;
          v9 = WdfFunctions.WdfCollectionGetCount(WdfDriverGlobals, *(WDFCOLLECTION *)&v4[5].field_14);
          if ( !v9 )
          {
LABEL_45:
            if ( !v4[5].field_1d )
            {
              v14 = *(_DWORD *)&v4->field_10;
              if ( v14 )
              {
                v33 = 0;
                v34 = 0;
                v35 = 0;
                v36 = 0;
                v37 = 0;
                v32 = 24;
                v33 = *(_DWORD *)&v4->field_0;
                v34 = *(_DWORD *)&v4->field_4;
                v35 = *(_DWORD *)&v4->field_8;
                v15 = *(_DWORD *)&v4->field_c;
                v37 = v14;
                v36 = v15;
                if ( dword_415994 )
                {
                  if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                    EventWrite_07(
                      ETW_RegistrationHandle_01,
                      &stru_40E3A8,
                      (const _GUID *)"Client state information",
                      "SendRPEClientStatusToNotifier",
                      "Client state information",
                      (unsigned int)v4);
                }
                v0 = off_4159D8(&v32);
                v29 = v0;
                if ( v0 >= 0 )
                {
                  v4[5].field_1d = 1;
                }
                else if ( dword_415994 && byte_415998 != 1 )
                {
                  EventWrite_04(
                    ETW_RegistrationHandle_01,
                    v21,
                    (const _GUID *)"client state information",
                    "SendRPEClientStatusToNotifier",
                    "client state information",
                    (unsigned int)v4,
                    v0);
                }
              }
            }
            result = (RPE_COMMAND_NOTIFICATION *)WdfFunctions.WdfCollectionGetCount(
                                                   WdfDriverGlobals,
                                                   *(WDFCOLLECTION *)&v4[5].field_18);
            v22 = result;
            v23 = 0;
            if ( result )
            {
              do
              {
                result = (RPE_COMMAND_NOTIFICATION *)WdfFunctions.WdfCollectionGetFirstItem(
                                                       WdfDriverGlobals,
                                                       *(_DWORD *)&v4[5].field_18);
                v24 = result;
                if ( result )
                {
                  result = (RPE_COMMAND_NOTIFICATION *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                                         WdfDriverGlobals,
                                                         result,
                                                         WDF_RPE_COMMAND_NOTIFICATION_TYPE_INFO.UniqueType);
                  if ( result )
                  {
                    *(_DWORD *)&result->field_4 |= 1u;
                    off_4159DC();
                    if ( v29 < 0 && dword_415994 && byte_415998 != 1 )
                      EventWrite_04(
                        ETW_RegistrationHandle_01,
                        v25,
                        (const _GUID *)"SendRPEClientStatusToNotifier",
                        "SendRPEClientStatusToNotifier",
                        "command information",
                        (unsigned int)v4,
                        v29);
                    WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, *(WDFCOLLECTION *)&v4[5].field_14, v24);
                    result = (RPE_COMMAND_NOTIFICATION *)((int (__fastcall *)(int, RPE_COMMAND_NOTIFICATION *))WdfFunctions.WdfObjectDelete)(
                                                           WdfDriverGlobals,
                                                           v24);
                  }
                  else if ( dword_415994 && byte_415998 != 1 )
                  {
                    result = (RPE_COMMAND_NOTIFICATION *)EventWrite_02(
                                                           ETW_RegistrationHandle_01,
                                                           &stru_40E368,
                                                           (const _GUID *)"SendRPEClientStatusToNotifier",
                                                           "SendRPEClientStatusToNotifier",
                                                           "Command notification context",
                                                           v24);
                  }
                }
                else if ( dword_415994 && byte_415998 != 1 )
                {
                  result = (RPE_COMMAND_NOTIFICATION *)EventWrite_06(
                                                         ETW_RegistrationHandle_01,
                                                         0,
                                                         (const _GUID *)"SendRPEClientStatusToNotifier",
                                                         "SendRPEClientStatusToNotifier",
                                                         "WdfCollectionFirstItem",
                                                         v23,
                                                         0,
                                                         *(_DWORD *)&v4[5].field_18,
                                                         v28,
                                                         v22,
                                                         0);
                }
                ++v23;
              }
              while ( v23 < (unsigned int)v22 );
              v0 = v29;
            }
            goto LABEL_106;
          }
          while ( 2 )
          {
            v10 = (void *)((int (__fastcall *)(int, _DWORD))WdfFunctions.WdfCollectionGetItem)(
                            WdfDriverGlobals,
                            *(_DWORD *)&v4[5].field_14);
            v11 = v10;
            if ( !v10 )
            {
              if ( dword_415994 && byte_415998 != 1 )
                EventWrite_06(
                  ETW_RegistrationHandle_01,
                  0,
                  (const _GUID *)"SendRPEClientStatusToNotifier",
                  "SendRPEClientStatusToNotifier",
                  "WdfCollectionGetItem",
                  v8,
                  0,
                  *(_DWORD *)&v4[5].field_14,
                  v28,
                  v9,
                  0);
              goto LABEL_44;
            }
            v12 = (RPE_CLIENT_NOTIFICATION *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                               WdfDriverGlobals,
                                               v10,
                                               WDF_RPE_CLIENT_NOTIFICATION_TYPE_INFO.UniqueType);
            v13 = v12;
            if ( !v12 )
            {
              if ( dword_415994 && byte_415998 != 1 )
                EventWrite_02(
                  ETW_RegistrationHandle_01,
                  &stru_40E368,
                  (const _GUID *)"SendRPEClientStatusToNotifier",
                  "SendRPEClientStatusToNotifier",
                  "Client state notification context",
                  v11);
              break;
            }
            if ( v12->field_2e == 1 )
            {
              if ( !v12->field_2c )
              {
                if ( dword_415994 )
                {
                  if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                    EventWrite_07(
                      ETW_RegistrationHandle_01,
                      &stru_40E3A8,
                      (const _GUID *)"SendRPEClientStatusToNotifier",
                      "SendRPEClientStatusToNotifier",
                      "Client state registration information",
                      (unsigned int)v4);
                }
                v18 = (const _EVENT_DESCRIPTOR *)off_4159E0(v13, &v13->field_10, *(_DWORD *)&v13->field_28);
                v29 = (int)v18;
                if ( (int)v18 < 0 )
                {
                  if ( dword_415994 && byte_415998 != 1 )
                    EventWrite_04(
                      ETW_RegistrationHandle_01,
                      v18,
                      (const _GUID *)"SendRPEClientStatusToNotifier",
                      "SendRPEClientStatusToNotifier",
                      "client state registration information",
                      (unsigned int)v4,
                      v18);
                  goto LABEL_64;
                }
                v13->field_2c = 1;
              }
            }
            else
            {
              if ( !v12->field_2c && !v12->field_2d )
              {
LABEL_64:
                WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, *(WDFCOLLECTION *)&v4[5].field_14, v11);
                WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v11);
                v0 = v29;
                goto LABEL_44;
              }
              if ( v12->field_2c == 1 && !v12->field_2d )
              {
                if ( dword_415994 )
                {
                  if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
                    EventWrite_07(
                      ETW_RegistrationHandle_01,
                      &stru_40E3A8,
                      (const _GUID *)"SendRPEClientStatusToNotifier",
                      "SendRPEClientStatusToNotifier",
                      "Client state deregistration information",
                      (unsigned int)v4);
                }
                v0 = off_4159E4(v13, &v13->field_10);
                v29 = v0;
                if ( v0 < 0 && dword_415994 && byte_415998 != 1 )
                  EventWrite_04(
                    ETW_RegistrationHandle_01,
                    v20,
                    (const _GUID *)"SendRPEClientStatusToNotifier",
                    "SendRPEClientStatusToNotifier",
                    "client state deregistration information",
                    (unsigned int)v4,
                    v0);
                WdfFunctions.WdfCollectionRemove(WdfDriverGlobals, *(WDFCOLLECTION *)&v4[5].field_14, v11);
                WdfFunctions.WdfObjectDelete(WdfDriverGlobals, v11);
LABEL_44:
                if ( ++v8 >= v9 )
                  goto LABEL_45;
                continue;
              }
            }
            break;
          }
          v0 = v29;
          goto LABEL_44;
        }
        if ( dword_415994 && byte_415998 != 1 )
          result = (RPE_COMMAND_NOTIFICATION *)EventWrite_02(
                                                 ETW_RegistrationHandle_01,
                                                 &stru_40E368,
                                                 (const _GUID *)"Client context",
                                                 "SendRPEClientStatusToNotifier",
                                                 "Client context",
                                                 v3);
      }
      else if ( dword_415994 )
      {
        if ( byte_415998 != 1 )
          result = (RPE_COMMAND_NOTIFICATION *)EventWrite_06(
                                                 ETW_RegistrationHandle_01,
                                                 EventDescriptor,
                                                 (const _GUID *)"WdfCollectionGetItem",
                                                 "SendRPEClientStatusToNotifier",
                                                 "WdfCollectionGetItem",
                                                 EventDescriptor,
                                                 0,
                                                 Collection_RPEClients,
                                                 v28,
                                                 v31,
                                                 0);
      }
LABEL_106:
      EventDescriptor = (_EVENT_DESCRIPTOR *)((char *)EventDescriptor + 1);
    }
    while ( EventDescriptor < (_EVENT_DESCRIPTOR *)v31 );
  }
  return result;
}


// Function: RpeInit
int __fastcall RpeInit(
        void *a1,
        void (__fastcall *a2)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *))
{
  unsigned __int8 v3; // r2
  int v4; // r3
  int v5; // r4
  int v7; // r0
  int v8; // r0
  WDFDRIVER v9; // r0
  _DRIVER_OBJECT *v10; // r0
  NTSTATUS v11; // r0
  unsigned __int8 v13; // r3
  _DWORD v15[9]; // [sp+10h] [bp-40h] BYREF

  do
  {
    __dmb(0xBu);
    do
      v3 = __ldrex(byte_415964);
    while ( __strex(v3 | 2, byte_415964) );
    __dmb(0xBu);
  }
  while ( (unsigned __int8)(v3 & 2) >> 1 );
  McGenEventRegister(&ETW_Provider_GUID_01, a2, &ETW_CallbackContext_01, &ETW_RegistrationHandle_01);
  v4 = dword_415994;
  if ( byte_415961 == 1 )
  {
    v5 = -536182525;
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E3B8,
        (const _GUID *)"RpeInit",
        "RpeInit",
        "RPE already initialized",
        -536182525);
  }
  else
  {
    if ( dword_415994 )
    {
      if ( (unsigned __int8)byte_415998 >= 5u || !byte_415998 )
      {
        EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)dword_415994, "RpeInit");
        v4 = dword_415994;
      }
    }
    if ( a1 )
    {
      dword_4159EC = (int)a1;
      v7 = WdfFunctions.WdfCollectionCreate(WdfDriverGlobals, 0, (WDFCOLLECTION *)&Collection_RPEClients);
      v5 = v7;
      if ( v7 >= 0 )
      {
        v15[1] = 0;
        v15[2] = 0;
        memset(&v15[5], 0, 12);
        v15[0] = 32;
        v15[3] = 1;
        v15[4] = 1;
        v8 = WdfFunctions.WdfWaitLockCreate(
               WdfDriverGlobals,
               (_WDF_OBJECT_ATTRIBUTES *)v15,
               (WDFWAITLOCK *)&dword_4159F0);
        v5 = v8;
        if ( v8 >= 0 )
        {
          byte_415962 = 0;
          v9 = WdfFunctions.WdfDeviceGetDriver(WdfDriverGlobals, a1);
          v10 = WdfFunctions.WdfDriverWdmGetDriverObject(WdfDriverGlobals, v9);
          v11 = IoRegisterPlugPlayNotification(
                  EventCategoryDeviceInterfaceChange,
                  1u,
                  &unk_40E208,
                  v10,
                  (DRIVER_NOTIFICATION_CALLBACK_ROUTINE *)RPEHelperEvtNotifyInterfaceChange,
                  0,
                  &dword_4159F4);
          v5 = v11;
          if ( v11 >= 0 )
          {
            dword_4159E8 = 1;
            byte_415961 = 1;
            if ( dword_415994 )
            {
              if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
                EventWrite_02(
                  ETW_RegistrationHandle_01,
                  &stru_40E308,
                  (const _GUID *)"RPE Init",
                  "RpeInit",
                  "RPE Init",
                  a1);
            }
          }
          else if ( dword_415994 && byte_415998 != 1 )
          {
            EventWrite_02(
              ETW_RegistrationHandle_01,
              &stru_40E348,
              (const _GUID *)"IoRegisterPlugPlayNotification",
              "RpeInit",
              "IoRegisterPlugPlayNotification",
              v11);
          }
        }
        else if ( dword_415994 && byte_415998 != 1 )
        {
          EventWrite_02(
            ETW_RegistrationHandle_01,
            &stru_40E348,
            (const _GUID *)"WdfWaitLockCreate",
            "RpeInit",
            "WdfWaitLockCreate",
            v8);
        }
      }
      else if ( dword_415994 && byte_415998 != 1 )
      {
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E348,
          (const _GUID *)"WdfCollectionObjectCreate for RpeClientList",
          "RpeInit",
          "WdfCollectionObjectCreate for RpeClientList",
          v7);
      }
    }
    else
    {
      v5 = -1073741811;
      if ( v4 && byte_415998 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E3B8,
          (const _GUID *)"wdfDevice is NULL",
          "RpeInit",
          "wdfDevice is NULL",
          -1073741811);
    }
  }
  __dmb(0xBu);
  do
    v13 = __ldrex(byte_415964);
  while ( __strex(v13 & 0xFD, byte_415964) );
  __dmb(0xBu);
  return v5;
}


// Function: _openRpenIoTarget
int openRpenIoTarget()
{
  BOOL v0; // r3
  int result; // r0
  int v2; // r0
  int v3; // r0
  const _EVENT_DESCRIPTOR *v4; // r2
  int v6; // r0
  char *v7; // [sp+0h] [bp-C0h]
  _DWORD v8[8]; // [sp+18h] [bp-A8h] BYREF
  _WDF_IO_TARGET_OPEN_PARAMS dest; // [sp+38h] [bp-88h] BYREF
  wchar_t v10[16]; // [sp+80h] [bp-40h] BYREF

  wcscpy(v10, L"\\Device\\RPEN");
  if ( dword_415994 )
  {
    v0 = (unsigned __int8)byte_415998 >= 5u || !byte_415998;
    if ( v0 )
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E2F8, (const _GUID *)v0, "_openRpenIoTarget");
  }
  result = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, dword_4159F0, 0);
  if ( result )
  {
    if ( dword_415994 )
    {
      if ( byte_415998 != 1 )
        return EventWrite_02(
                 ETW_RegistrationHandle_01,
                 &stru_40E348,
                 (const _GUID *)"WdfWaitLockAcquire",
                 "_openRpenIoTarget",
                 "WdfWaitLockAcquire",
                 result);
    }
  }
  else
  {
    if ( dword_4159EC )
    {
      v8[1] = 0;
      v8[2] = 0;
      memset(&v8[5], 0, 12);
      v8[0] = 32;
      v8[3] = 1;
      v8[4] = 1;
      v2 = WdfFunctions.WdfIoTargetCreate(
             WdfDriverGlobals,
             (WDFDEVICE)dword_4159EC,
             (_WDF_OBJECT_ATTRIBUTES *)v8,
             (WDFIOTARGET *)&dword_4159F8);
      if ( v2 >= 0 )
      {
        memset(&dest, 0, sizeof(dest));
        dest.Size = 72;
        dest.Type = WdfIoTargetOpenByName;
        *(_DWORD *)&dest.TargetDeviceName.Length = 1703960;
        dest.TargetDeviceName.Buffer = v10;
        dest.DesiredAccess = 2031616;
        dest.CreateOptions = 64;
        dest.CreateDisposition = 1;
        dest.ShareAccess = 3;
        dest.EvtIoTargetQueryRemove = (NTSTATUS (__fastcall *)(WDFIOTARGET))RPEHelperEvtIoTargetQueryRemove;
        dest.EvtIoTargetRemoveComplete = (void (__fastcall *)(WDFIOTARGET))RPEHelperEvtIoTargetRemoveComplete;
        dest.EvtIoTargetRemoveCanceled = (void (__fastcall *)(WDFIOTARGET))RPEHelperEvtIoTargetRemoveCanceled;
        v3 = ((int (__fastcall *)(int, int, _WDF_IO_TARGET_OPEN_PARAMS *))WdfFunctions.WdfIoTargetOpen)(
               WdfDriverGlobals,
               dword_4159F8,
               &dest);
        if ( v3 >= 0 )
        {
          if ( dword_415994 )
          {
            if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
              EventWrite_08(ETW_RegistrationHandle_01, v4, (const _GUID *)dword_4159F8, (int)v7);
          }
          v6 = WdfFunctions.WdfIoTargetQueryForInterface(
                 WdfDriverGlobals,
                 (WDFIOTARGET)dword_4159F8,
                 (_GUID *)&unk_40E208,
                 (_INTERFACE *)&unk_4159C0,
                 40,
                 1,
                 0);
          if ( v6 >= 0 )
          {
            byte_415962 = 1;
            SendRPEClientStatusToNotifier();
          }
          else if ( dword_415994 && byte_415998 != 1 )
          {
            EventWrite_02(
              ETW_RegistrationHandle_01,
              &stru_40E348,
              (const _GUID *)"WdfIoTargetQueryForInterface",
              "_openRpenIoTarget",
              "WdfIoTargetQueryForInterface",
              v6);
          }
        }
        else
        {
          if ( dword_415994 && byte_415998 != 1 )
            EventWrite_02(
              ETW_RegistrationHandle_01,
              &stru_40E348,
              (const _GUID *)"WdfIoTargetOpen",
              "_openRpenIoTarget",
              "WdfIoTargetOpen",
              v3);
          WdfFunctions.WdfObjectDelete(WdfDriverGlobals, (WDFOBJECT)dword_4159F8);
        }
      }
      else if ( dword_415994 && byte_415998 != 1 )
      {
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E348,
          (const _GUID *)"WdfIoTargetCreate",
          "_openRpenIoTarget",
          "WdfIoTargetCreate",
          v2);
      }
    }
    else if ( dword_415994 && byte_415998 != 1 )
    {
      EventWrite_05(ETW_RegistrationHandle_01, &stru_40E318, (const _GUID *)(byte_415998 != 1), "_openRpenIoTarget");
    }
    return ((int (__fastcall *)(int, WDFWAITLOCK))WdfFunctions.WdfWaitLockRelease)(WdfDriverGlobals, dword_4159F0);
  }
  return result;
}


// Function: _getClientContextByGUID
RPE_CLIENT_CONTEXT *__fastcall getClientContextByGUID(GUID *guid, _DWORD *out_RPEClient)
{
  ULONG collection_size; // r7
  ULONG index; // r4
  WDFOBJECT v5; // r0
  WDFOBJECT v6; // r6
  RPE_CLIENT_CONTEXT *v7; // r0
  RPE_CLIENT_CONTEXT *v8; // r5
  int v10; // [sp+14h] [bp-2Ch]

  collection_size = WdfFunctions.WdfCollectionGetCount(WdfDriverGlobals, Collection_RPEClients);
  index = 0;
  if ( collection_size )
  {
    while ( 1 )
    {
      v5 = WdfFunctions.WdfCollectionGetItem(WdfDriverGlobals, Collection_RPEClients, index);
      v6 = v5;
      if ( !v5 )
      {
        if ( dword_415994 && byte_415998 != 1 )
          EventWrite_06(
            ETW_RegistrationHandle_01,
            0,
            (const _GUID *)&ETW_RegistrationHandle_01,
            "_getClientContextByGUID",
            "WdfCollectionGetItem",
            index,
            0,
            Collection_RPEClients,
            v10,
            collection_size,
            0);
        return 0;
      }
      v7 = (RPE_CLIENT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                   WdfDriverGlobals,
                                   v5,
                                   WDF_RPE_CLIENT_CONTEXT_TYPE_INFO.UniqueType);
      v8 = v7;
      if ( !v7 )
        break;
      if ( !memcmp(v7, guid, 0x10u) )
      {
        if ( out_RPEClient )                    // GUID found
          *out_RPEClient = v6;
        return v8;
      }
      if ( ++index >= collection_size )
        return 0;
    }
    if ( dword_415994 && byte_415998 != 1 )
    {
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E368,
        (const _GUID *)&ETW_RegistrationHandle_01,
        "_getClientContextByGUID",
        "Client context",
        v6);
      return 0;
    }
  }
  return 0;
}


// Function: RPEHelperEvtIoTargetQueryRemove
NTSTATUS __fastcall RPEHelperEvtIoTargetQueryRemove(int a1)
{
  unsigned __int8 v2; // r2
  unsigned __int8 v3; // r3
  NTSTATUS v5; // r7
  unsigned __int8 v6; // r3
  unsigned __int8 v7; // r3

  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
      EventWrite_01(
        ETW_RegistrationHandle_01,
        &stru_40E2D8,
        (const _GUID *)"Removal",
        "RPEHelperEvtIoTargetQueryRemove",
        "Removal");
  }
  do
  {
    __dmb(0xBu);
    do
      v2 = __ldrex(byte_415964);
    while ( __strex(v2 | 2, byte_415964) );
    __dmb(0xBu);
  }
  while ( (unsigned __int8)(v2 & 2) >> 1 );
  if ( dword_4159F0 )
  {
    v5 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, (WDFWAITLOCK)dword_4159F0, 0);
    if ( v5 )
    {
      if ( dword_415994 && byte_415998 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_01,
          &stru_40E348,
          (const _GUID *)"WdfWaitLockAcquire",
          "RPEHelperEvtIoTargetQueryRemove",
          "WdfWaitLockAcquire",
          v5);
      __dmb(0xBu);
      do
        v6 = __ldrex(byte_415964);
      while ( __strex(v6 & 0xFD, byte_415964) );
      __dmb(0xBu);
      return v5;
    }
    else
    {
      __dmb(0xBu);
      do
        v7 = __ldrex(byte_415964);
      while ( __strex(v7 & 0xFD, byte_415964) );
      __dmb(0xBu);
      if ( dword_4159EC )
      {
        if ( byte_415962 == 1 && a1 == dword_4159F8 )
        {
          byte_415962 = 0;
          if ( dword_4159F8 )
          {
            WdfFunctions.WdfIoTargetClose(WdfDriverGlobals, (WDFIOTARGET)dword_4159F8);
            WdfFunctions.WdfObjectDelete(WdfDriverGlobals, (WDFOBJECT)dword_4159F8);
            dword_4159F8 = 0;
          }
        }
      }
      else if ( dword_415994 && byte_415998 != 1 )
      {
        EventWrite_05(
          ETW_RegistrationHandle_01,
          &stru_40E318,
          (const _GUID *)(byte_415998 != 1),
          "RPEHelperEvtIoTargetQueryRemove");
      }
      WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, (WDFWAITLOCK)dword_4159F0);
      return 0;
    }
  }
  else
  {
    __dmb(0xBu);
    do
      v3 = __ldrex(byte_415964);
    while ( __strex(v3 & 0xFD, byte_415964) );
    __dmb(0xBu);
    return 0;
  }
}


// Function: RPEHelperEvtIoTargetRemoveComplete
void RPEHelperEvtIoTargetRemoveComplete()
{
  unsigned __int8 v1; // r2
  NTSTATUS v2; // r0
  unsigned __int8 v3; // r3
  unsigned __int8 v4; // r3

  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
      EventWrite_01(
        ETW_RegistrationHandle_01,
        &stru_40E2D8,
        (const _GUID *)"Removal",
        "RPEHelperEvtIoTargetRemoveComplete",
        "Removal");
  }
  do
  {
    __dmb(0xBu);
    do
      v1 = __ldrex(byte_415964);
    while ( __strex(v1 | 2, byte_415964) );
    __dmb(0xBu);
  }
  while ( (unsigned __int8)(v1 & 2) >> 1 );
  if ( !dword_4159F0 )
    goto LABEL_16;
  v2 = WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, (WDFWAITLOCK)dword_4159F0, 0);
  if ( v2 )
  {
    if ( dword_415994 && byte_415998 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_01,
        &stru_40E348,
        (const _GUID *)"WdfWaitLockAcquire",
        "RPEHelperEvtIoTargetRemoveComplete",
        "WdfWaitLockAcquire",
        v2);
LABEL_16:
    __dmb(0xBu);
    do
      v3 = __ldrex(byte_415964);
    while ( __strex(v3 & 0xFD, byte_415964) );
    __dmb(0xBu);
    return;
  }
  __dmb(0xBu);
  do
    v4 = __ldrex(byte_415964);
  while ( __strex(v4 & 0xFD, byte_415964) );
  __dmb(0xBu);
  if ( dword_4159EC )
  {
    if ( byte_415962 == 1 )
    {
      byte_415962 = 0;
      if ( dword_4159F8 )
      {
        WdfFunctions.WdfIoTargetClose(WdfDriverGlobals, (WDFIOTARGET)dword_4159F8);
        WdfFunctions.WdfObjectDelete(WdfDriverGlobals, (WDFOBJECT)dword_4159F8);
        dword_4159F8 = 0;
      }
    }
  }
  else if ( dword_415994 && byte_415998 != 1 )
  {
    EventWrite_05(
      ETW_RegistrationHandle_01,
      &stru_40E318,
      (const _GUID *)(byte_415998 != 1),
      "RPEHelperEvtIoTargetRemoveComplete");
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, (WDFWAITLOCK)dword_4159F0);
    return;
  }
  WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, (WDFWAITLOCK)dword_4159F0);
}


// Function: RPEHelperEvtIoTargetRemoveCanceled
int RPEHelperEvtIoTargetRemoveCanceled()
{
  int result; // r0

  if ( dword_415994 )
  {
    if ( (unsigned __int8)byte_415998 >= 4u || !byte_415998 )
      result = EventWrite_01(
                 ETW_RegistrationHandle_01,
                 &stru_40E2D8,
                 (const _GUID *)&ETW_RegistrationHandle_01,
                 "RPEHelperEvtIoTargetRemoveCanceled",
                 "Removal canceled");
  }
  if ( !byte_415962 )
    return openRpenIoTarget();
  return result;
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

  v2 = &unk_40F280;
  if ( off_40F284 != &unk_40F278 && &unk_40F280 <= off_40F284 )
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
    while ( v2 <= (_DWORD *)off_40F284 );
  }
}


// Function: FxStubBindClasses
int __fastcall FxStubBindClasses(_WDF_BIND_INFO *WdfBindInfo)
{
  int result; // r0

  result = 0;
  if ( &unk_40F278 > &unk_40F280 )
    return -1073741701;
  return result;
}


// Function: FxStubInitTypes
int __fastcall FxStubInitTypes()
{
  if ( &unk_40F288 <= &unk_40F290 )
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


// Function: _memcpy_forward_new
int __fastcall memcpy_forward_new(int result, unsigned int a2, int a3)
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
        memcpy_forward_large_neon(result, (__int64 *)a2, a3, result);
      else
        result = ((int (*)(void))memcpy_forward_large_func)();
      break;
  }
  return result;
}


// Function: _memcpy_forward_large_integer
void __fastcall memcpy_forward_large_integer(int a1, char *a2, unsigned int a3, _BYTE *a4)
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
    JUMPOUT(0x40CA2A);
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


// Function: _memcpy_forward_large_neon
void __fastcall memcpy_forward_large_neon(int a1, __int64 *a2, unsigned int a3, int a4)
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
  __int64 v15; // r4

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
    v15 = *a2++;
    *(_QWORD *)a4 = v15;
    a4 += 8;
    v4 = i >= 8;
  }
  if ( i != -8 )
    JUMPOUT(0x40CA2A);
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
    return (void *)memcpy_forward_new((int)dest, (unsigned int)src, count);
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
        dest = (void *)memcpy_reverse_large_neon((int)dest, (int)src, count);
      else
        dest = ((void *(*)(void))memcpy_reverse_large_func)();
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
    JUMPOUT(0x40CC70);
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


// Function: _memcpy_reverse_large_neon
int __fastcall memcpy_reverse_large_neon(int result, int a2, unsigned int a3)
{
  unsigned int v3; // r3
  unsigned int v4; // r1
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
  if ( v4 == i + 8 )
    JUMPOUT(0x40CEDC);
  JUMPOUT(0x40CC70);
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
    memcpy_forward_large_func = (unsigned int)memcpy_forward_large_neon;
    memcpy_reverse_large_func = (unsigned int)memcpy_reverse_large_neon;
    return (*v0)();
  }
  if ( !MEMORY[0x7FFE028E] )
    goto LABEL_7;
LABEL_6:
  memcpy_forward_large_func = (unsigned int)memcpy_forward_large_integer;
  memcpy_reverse_large_func = (unsigned int)memcpy_reverse_large_integer;
  return (*v0)();
}


// Function: strlen
// attributes: thunk
size_t __fastcall strlen(char *str)
{
  return __imp_strlen(str);
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


// Function: strncmp
// attributes: thunk
int __fastcall strncmp(char *string1, char *string2, size_t count)
{
  return __imp_strncmp(string1, string2, count);
}


// Function: memcmp
int __fastcall memcmp(const void *buffer1, const void *buffer2, size_t count)
{
  bool v3; // cc
  int v4; // r3
  int v5; // t1
  int v6; // t1
  int v7; // r12
  int v8; // r3
  int v10; // r3
  int v11; // t1
  unsigned __int8 v12; // r12
  int v13; // t1
  int v14; // r3
  int v15; // r3
  int v16; // t1
  int v17; // r12
  int v18; // t1

  if ( (int)count < 4 )
  {
LABEL_18:
    if ( !count )
      return 0;
    goto LABEL_19;
  }
  if ( (((unsigned int)buffer1 | (unsigned int)buffer2) & 1) != 0 )
  {
    do
    {
LABEL_19:
      v16 = *(unsigned __int8 *)buffer1;
      buffer1 = (char *)buffer1 + 1;
      v15 = v16;
      v18 = *(unsigned __int8 *)buffer2;
      buffer2 = (char *)buffer2 + 1;
      v17 = v18;
      --count;
    }
    while ( count && v15 == v17 );
    return v15 - v17;
  }
  if ( (((unsigned __int8)buffer1 | (unsigned __int8)buffer2) & 2) != 0 )
  {
    do
    {
      v3 = (int)count < 2;
      count -= 2;
      if ( v3 )
      {
LABEL_17:
        count += 2;
        goto LABEL_18;
      }
      v11 = *(unsigned __int16 *)buffer1;
      buffer1 = (char *)buffer1 + 2;
      v10 = v11;
      v13 = *(unsigned __int16 *)buffer2;
      buffer2 = (char *)buffer2 + 2;
      v12 = v13;
      v14 = v10 - v13;
    }
    while ( !v14 );
    if ( (_BYTE)v14 )
      return (unsigned __int8)*((char *)buffer1 - 2) - v12;
    else
      return v14 >> 8;
  }
  else
  {
    do
    {
      v3 = (int)count < 4;
      count -= 4;
      if ( v3 )
      {
        count += 2;
        goto LABEL_17;
      }
      v5 = *(_DWORD *)buffer1;
      buffer1 = (char *)buffer1 + 4;
      v4 = v5;
      v6 = *(_DWORD *)buffer2;
      buffer2 = (char *)buffer2 + 4;
      v7 = v6 ^ v4;
    }
    while ( v6 == v4 );
    v8 = 4;
    if ( !(_BYTE)v7 )
    {
      v8 = 3;
      if ( (v7 & 0xFF00) == 0 )
      {
        v8 = 2;
        if ( (v7 & 0xFF0000) == 0 )
          v8 = 1;
      }
    }
    return (unsigned __int8)*((char *)buffer1 - v8) - (unsigned __int8)*((char *)buffer2 - v8);
  }
}


// Function: strcmp
// attributes: thunk
int __fastcall strcmp(char *string1, char *string2)
{
  return __imp_strcmp(string1, string2);
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
            memcpy_forward_new((int)v7 + v13 + 2, *((_DWORD *)v10 + 1), *v10);
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

  v2 = &dword_415AA0;
  if ( off_40F178 != (_UNKNOWN *)&dword_415AA0 )
  {
    off_40F178 = &dword_415AA0;
    if ( WPPTraceSuite == WppTraceServer08 )
    {
      do
      {
        v3 = v2[1];
        v4 = pfnEtwRegisterClassicProvider;
        v2[10] = 0;
        v2[11] = 0;
        ((void (__fastcall *)(int, _DWORD, int (*)(), int *))v4)(v3, 0, SmdSetContextFields, v2);
        v2 = (int *)v2[2];
      }
      while ( v2 );
    }
    else if ( WPPTraceSuite == WppTraceWinXP )
    {
      dword_415AA0 = (int)WppTraceCallback;
      IoWMIRegistrationControl((_DEVICE_OBJECT *)&dword_415AA0, 0x80010001);
    }
  }
}


// Function: WppCleanupKm
void __fastcall WppCleanupKm(_DEVICE_OBJECT *DeviceObject)
{
  _QWORD *v1; // r4
  unsigned __int64 v2; // r0

  v1 = off_40F178;
  if ( off_40F178 == (_UNKNOWN *)&off_40F178 )
    return;
  if ( WPPTraceSuite != WppTraceServer08 )
  {
    if ( WPPTraceSuite == WppTraceWinXP )
      IoWMIRegistrationControl((_DEVICE_OBJECT *)off_40F178, 0x80000002);
    goto LABEL_10;
  }
  if ( !off_40F178 )
  {
LABEL_10:
    off_40F178 = &off_40F178;
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
  off_40F178 = &off_40F178;
}


// Function: SmdEvtDeviceAdd
NTSTATUS __fastcall SmdEvtDeviceAdd(WDFDRIVER Driver, WDFDEVICE_INIT *DeviceInit)
{
  unsigned int v3; // r3
  unsigned __int64 v4; // r0
  SMD_DRIVER_CONTEXT *v5; // r9
  NTSTATUS status; // r4
  unsigned __int64 v7; // r0
  NTSTATUS v9; // r0
  unsigned int v10; // r3
  unsigned __int64 v11; // r0
  NTSTATUS v12; // r0
  unsigned int v13; // r3
  unsigned __int64 v14; // r0
  unsigned __int64 v15; // r0
  int v16; // r0
  unsigned int v17; // r3
  unsigned __int64 v18; // r0
  NTSTATUS v19; // r0
  unsigned int v20; // r3
  unsigned __int64 v21; // r0
  NTSTATUS v22; // r0
  unsigned int v23; // r3
  unsigned __int64 v24; // r0
  int v25; // r0
  unsigned int v26; // r3
  unsigned __int64 v27; // r0
  int v28; // r0
  unsigned int v29; // r3
  unsigned __int64 v30; // r0
  int v31; // r0
  unsigned int v32; // r3
  unsigned __int64 v33; // r0
  void *Device; // [sp+10h] [bp-158h] BYREF
  WDFDEVICE_INIT *v36; // [sp+14h] [bp-154h] BYREF
  _WDF_OBJECT_ATTRIBUTES DeviceAttributes; // [sp+18h] [bp-150h] BYREF
  UNICODE_STRING v38; // [sp+38h] [bp-130h] BYREF
  QUERY_INTERFACE query_interface; // [sp+40h] [bp-128h] BYREF
  _WDF_QUERY_INTERFACE_CONFIG InterfaceConfig; // [sp+80h] [bp-E8h] BYREF
  _WDF_IO_QUEUE_CONFIG Config; // [sp+98h] [bp-D0h] BYREF
  _WDF_FILEOBJECT_CONFIG FileObjectConfig; // [sp+D0h] [bp-98h] BYREF
  _WDF_PNPPOWER_EVENT_CALLBACKS PnpPowerEventCallbacks; // [sp+E8h] [bp-80h] BYREF
  wchar_t v44[12]; // [sp+130h] [bp-38h] BYREF

  memset(&query_interface, 0, sizeof(query_interface));
  v36 = DeviceInit;
  wcscpy(v44, L"\\Device\\SMD");
  v38.Length = 22;
  v38.MaximumLength = 24;
  v38.Buffer = v44;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v3 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v3 >= 4 )
    {
      HIDWORD(v4) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v4) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_02(v4, 0xDu, v3, Driver);
    }
  }
  v5 = (SMD_DRIVER_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                               WdfDriverGlobals,
                               Driver,
                               WDF_SMD_DRIVER_CONTEXT_TYPE_INFO.UniqueType);
  if ( v5 )
  {
    WdfFunctions.WdfDeviceInitSetIoType(WdfDriverGlobals, v36, WdfDeviceIoNeither);
    v9 = WdfFunctions.WdfDeviceInitAssignName(WdfDriverGlobals, v36, &v38);
    status = v9;
    if ( v9 >= STATUS_SUCCESS )
    {
      memset(&PnpPowerEventCallbacks, 0, sizeof(PnpPowerEventCallbacks));
      PnpPowerEventCallbacks.Size = 72;
      PnpPowerEventCallbacks.EvtDevicePrepareHardware = EvtWdfDevicePrepareHardware;
      PnpPowerEventCallbacks.EvtDeviceReleaseHardware = EvtWdfDeviceReleaseHardware;
      PnpPowerEventCallbacks.EvtDeviceSurpriseRemoval = EvtWdfDeviceSurpriseRemoval;
      PnpPowerEventCallbacks.EvtDeviceSelfManagedIoInit = EvtWdfDeviceSelfManagedIoInit;
      PnpPowerEventCallbacks.EvtDeviceSelfManagedIoSuspend = EvtWdfDeviceSelfManagedIoSuspend;
      PnpPowerEventCallbacks.EvtDeviceSelfManagedIoRestart = EvtWdfDeviceSelfManagedIoRestart;
      PnpPowerEventCallbacks.EvtDeviceSelfManagedIoFlush = EvtWdfDeviceSelfManagedIoFlush;
      PnpPowerEventCallbacks.EvtDeviceSelfManagedIoCleanup = EvtWdfDeviceSelfManagedIoCleanup;
      WdfFunctions.WdfDeviceInitSetPnpPowerEventCallbacks(WdfDriverGlobals, v36, &PnpPowerEventCallbacks);
      WdfFunctions.WdfDeviceInitSetPowerPolicyOwnership(WdfDriverGlobals, v36, FALSE);
      FileObjectConfig.Size = 24;
      FileObjectConfig.EvtDeviceFileCreate = EvtWdfDeviceFileCreate;
      FileObjectConfig.EvtFileClose = EvtWdfFileClose;
      FileObjectConfig.EvtFileCleanup = 0;
      FileObjectConfig.FileObjectClass = WdfFileObjectWdfCannotUseFsContexts;
      FileObjectConfig.AutoForwardCleanupClose = WdfUseDefault;
      WdfFunctions.WdfDeviceInitSetFileObjectConfig(WdfDriverGlobals, v36, &FileObjectConfig, NULL);
      DeviceAttributes.EvtDestroyCallback = 0;
      memset(&DeviceAttributes.ParentObject, 0, 12);
      DeviceAttributes.Size = 32;
      DeviceAttributes.ExecutionLevel = WdfExecutionLevelInheritFromParent;
      DeviceAttributes.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
      DeviceAttributes.EvtCleanupCallback = EvtWdfObjectContextCleanup;
      v12 = WdfFunctions.WdfDeviceCreate(WdfDriverGlobals, &v36, &DeviceAttributes, &Device);
      status = v12;
      if ( v12 >= STATUS_SUCCESS )
      {
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
        {
          LODWORD(v15) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v15) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v15, 0x11u, (int)Device, Device);
        }
        v16 = smd_init(Device);
        status = v16;
        if ( v16 )
        {
          if ( dword_40FBB4 && byte_40FBB8 != 1 )
            EventWrite_02(
              ETW_RegistrationHandle_02,
              &stru_40E368,
              (const _GUID *)&ETW_RegistrationHandle_02,
              "SmdEvtDeviceAdd",
              "smd_initialize failed with",
              v16);
          if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
          {
            v17 = *((unsigned __int8 *)off_40F178 + 29);
            if ( v17 >= 2 )
            {
              LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_02(v18, 0x12u, v17, status);
              return status;
            }
          }
        }
        else
        {
          v19 = WdfFunctions.WdfDeviceCreateDeviceInterface(WdfDriverGlobals, Device, &InterfaceClassGUID_00, NULL);
          status = v19;
          if ( v19 >= STATUS_SUCCESS )
          {
            WdfFunctions.WdfDeviceSetStaticStopRemove(WdfDriverGlobals, Device, FALSE);
            *(_DWORD *)&Config.AllowZeroLengthRequests = 257;
            memset(&Config.EvtIoRead, 0, 36);
            Config.Size = 56;
            Config.DispatchType = WdfIoQueueDispatchSequential;
            Config.EvtIoDefault = EvtWdfIoQueueIoDefault;
            Config.PowerManaged = WdfFalse;
            DeviceAttributes.EvtCleanupCallback = 0;
            DeviceAttributes.EvtDestroyCallback = 0;
            memset(&DeviceAttributes.ParentObject, 0, 12);
            DeviceAttributes.Size = 32;
            DeviceAttributes.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
            DeviceAttributes.ExecutionLevel = WdfExecutionLevelPassive;
            v22 = WdfFunctions.WdfIoQueueCreate(WdfDriverGlobals, Device, &Config, &DeviceAttributes, (WDFQUEUE *)v5);
            status = v22;
            if ( v22 >= STATUS_SUCCESS )
            {
              v25 = WdfFunctions.WdfLookasideListCreate(
                      WdfDriverGlobals,
                      NULL,
                      12,
                      NonPagedPoolNx,
                      NULL,
                      'cvoi',
                      &WDFLOOKASIDE_size_12);
              status = v25;
              if ( v25 >= STATUS_SUCCESS )
              {
                v28 = WdfFunctions.WdfDeviceCreateDeviceInterface(
                        WdfDriverGlobals,
                        Device,
                        &GUID_SMD_Lite_API_interface,
                        NULL);
                status = v28;
                if ( v28 >= STATUS_SUCCESS )
                {
                  query_interface.Size = 56;
                  query_interface.InterfaceFunction_00 = (int)InterfaceFunction_00;
                  query_interface.InterfaceFunction_01 = (int)InterfaceFunction_01;
                  query_interface.InterfaceFunction_02 = (int)InterfaceFunction_02;
                  query_interface.InterfaceFunction_03 = (int)InterfaceFunction_03;
                  query_interface.InterfaceFunction_04 = (int)InterfaceFunction_04;
                  query_interface.InterfaceFunction_05 = (int)InterfaceFunction_05;
                  query_interface.InterfaceFunction_06 = (int)InterfaceFunction_06;
                  query_interface.InterfaceFunction_07 = (int)InterfaceFunction_07;
                  query_interface.InterfaceFunction_08 = (int)InterfaceFunction_08;
                  query_interface.InterfaceFunction_09 = (int)InterfaceFunction_09;
                  memset(&InterfaceConfig.SendQueryToParentStack, 0, 12);
                  InterfaceConfig.Size = 24;
                  InterfaceConfig.Interface = (_INTERFACE *)&query_interface;
                  InterfaceConfig.InterfaceType = &GUID_SMD_Lite_API_interface;
                  v31 = WdfFunctions.WdfDeviceAddQueryInterface(WdfDriverGlobals, Device, &InterfaceConfig);
                  status = v31;
                  if ( v31 >= STATUS_SUCCESS )
                  {
                    return SetupRPE(Device);
                  }
                  else
                  {
                    if ( dword_40FBB4 && byte_40FBB8 != 1 )
                      EventWrite_02(
                        ETW_RegistrationHandle_02,
                        &stru_40E3B8,
                        (const _GUID *)&ETW_RegistrationHandle_02,
                        "SmdEvtDeviceAdd",
                        "WdfDeviceAddQueryInterface for SMD Lite API interface",
                        v31);
                    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                    {
                      v32 = *((unsigned __int8 *)off_40F178 + 29);
                      if ( v32 >= 2 )
                      {
                        LODWORD(v33) = *((_DWORD *)off_40F178 + 4);
                        HIDWORD(v33) = *((_DWORD *)off_40F178 + 5);
                        DoTraceMessage_02(v33, 0x17u, v32, status);
                        return status;
                      }
                    }
                  }
                }
                else
                {
                  if ( dword_40FBB4 && byte_40FBB8 != 1 )
                    EventWrite_02(
                      ETW_RegistrationHandle_02,
                      &stru_40E3B8,
                      (const _GUID *)&ETW_RegistrationHandle_02,
                      "SmdEvtDeviceAdd",
                      "WdfDeviceCreateDeviceInterface for SMD Lite API interface",
                      v28);
                  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                  {
                    v29 = *((unsigned __int8 *)off_40F178 + 29);
                    if ( v29 >= 2 )
                    {
                      LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
                      HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
                      DoTraceMessage_02(v30, 0x16u, v29, status);
                      return status;
                    }
                  }
                }
              }
              else
              {
                if ( dword_40FBB4 && byte_40FBB8 != 1 )
                  EventWrite_02(
                    ETW_RegistrationHandle_02,
                    &stru_40E3B8,
                    (const _GUID *)&ETW_RegistrationHandle_02,
                    "SmdEvtDeviceAdd",
                    "WdfLookasideListCreate",
                    v25);
                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                {
                  v26 = *((unsigned __int8 *)off_40F178 + 29);
                  if ( v26 >= 2 )
                  {
                    LODWORD(v27) = *((_DWORD *)off_40F178 + 4);
                    HIDWORD(v27) = *((_DWORD *)off_40F178 + 5);
                    DoTraceMessage_02(v27, 0x15u, v26, status);
                    return status;
                  }
                }
              }
            }
            else
            {
              if ( dword_40FBB4 && byte_40FBB8 != 1 )
                EventWrite_02(
                  ETW_RegistrationHandle_02,
                  &stru_40E3B8,
                  (const _GUID *)&ETW_RegistrationHandle_02,
                  "SmdEvtDeviceAdd",
                  "WdfIoQueueCreate",
                  v22);
              if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
              {
                v23 = *((unsigned __int8 *)off_40F178 + 29);
                if ( v23 >= 2 )
                {
                  LODWORD(v24) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v24) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_02(v24, 0x14u, v23, status);
                  return status;
                }
              }
            }
          }
          else
          {
            if ( dword_40FBB4 && byte_40FBB8 != 1 )
              EventWrite_02(
                ETW_RegistrationHandle_02,
                &stru_40E3B8,
                (const _GUID *)&ETW_RegistrationHandle_02,
                "SmdEvtDeviceAdd",
                "WdfDeviceCreateDeviceInterface",
                v19);
            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
            {
              v20 = *((unsigned __int8 *)off_40F178 + 29);
              if ( v20 >= 2 )
              {
                LODWORD(v21) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v21) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v21, 0x13u, v20, status);
                return status;
              }
            }
          }
        }
      }
      else
      {
        if ( dword_40FBB4 && byte_40FBB8 != 1 )
          EventWrite_02(
            ETW_RegistrationHandle_02,
            &stru_40E3B8,
            (const _GUID *)&ETW_RegistrationHandle_02,
            "SmdEvtDeviceAdd",
            "WdfDeviceCreate",
            v12);
        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
        {
          v13 = *((unsigned __int8 *)off_40F178 + 29);
          if ( v13 >= 2 )
          {
            LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
            DoTraceMessage_02(v14, 0x10u, v13, status);
            return status;
          }
        }
      }
    }
    else
    {
      if ( dword_40FBB4 && byte_40FBB8 != 1 )
        EventWrite_02(
          ETW_RegistrationHandle_02,
          &stru_40E3B8,
          (const _GUID *)&ETW_RegistrationHandle_02,
          "SmdEvtDeviceAdd",
          "WdfDeviceInitAssignName",
          v9);
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v10 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v10 >= 2 )
        {
          LODWORD(v11) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v11) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v11, 0xFu, v10, status);
          return status;
        }
      }
    }
  }
  else
  {
    status = STATUS_IO_DEVICE_ERROR;
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      EventWrite_03(
        ETW_RegistrationHandle_02,
        &stru_40E160,
        (const _GUID *)&ETW_RegistrationHandle_02,
        "SmdEvtDeviceAdd",
        "Driver context",
        Driver,
        STATUS_IO_DEVICE_ERROR);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v7) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v7) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v7, 0xEu);
      return STATUS_IO_DEVICE_ERROR;
    }
  }
  return status;
}


// Function: EvtWdfIoQueueIoDefault
void __fastcall EvtWdfIoQueueIoDefault(WDFQUEUE Queue, WDFREQUEST Request)
{
  void *v3; // r0
  NTSTATUS v4; // r4
  unsigned __int64 v5; // r0
  SMD_PORT_CONTEXT *v6; // r0
  SMD_PORT_CONTEXT *v7; // r5
  unsigned __int64 v8; // r0
  int v9; // r3
  unsigned __int64 v10; // r0
  int v11; // r0
  unsigned __int64 v12; // r0
  unsigned __int64 v13; // r0
  int v14; // [sp+4h] [bp-44h]
  _DWORD *v15; // [sp+8h] [bp-40h] BYREF
  _DWORD v16[8]; // [sp+10h] [bp-38h] BYREF

  v15 = 0;
  v3 = (void *)((int (__fastcall *)(int))WdfFunctions.WdfRequestGetFileObject)(WdfDriverGlobals);
  if ( !v3 )
  {
    v4 = -1073741808;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v5) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v5) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v5, 0x23u);
    }
LABEL_22:
    WdfFunctions.WdfRequestCompleteWithInformation(WdfDriverGlobals, Request, v4, 0);
    return;
  }
  v6 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                             WdfDriverGlobals,
                             v3,
                             WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v7 = v6;
  if ( !v6 )
  {
    v4 = -1073741808;
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v8, 0x24u);
    }
    goto LABEL_22;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v9 = *(_DWORD *)&v6->field_0;
    LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v10, 0x25u, v9, *(_DWORD *)&v7->field_0);
  }
  v16[1] = 0;
  v16[2] = 0;
  v16[5] = 0;
  v16[6] = 0;
  v16[0] = 32;
  v16[3] = 1;
  v16[4] = 1;
  v16[7] = WDF_SMD_REQUEST_CONTEXT_TYPE_INFO.UniqueType;
  v11 = WdfFunctions.WdfObjectAllocateContext(WdfDriverGlobals, Request, (_WDF_OBJECT_ATTRIBUTES *)v16, (PVOID *)&v15);
  if ( v11 < 0 && (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 3u )
  {
    HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
    v14 = v11;
    LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
    DoTraceMessage_03(v12, 0x26u, *(_DWORD *)&v7->field_0, *(_DWORD *)&v7->field_0, v14);
  }
  if ( v15 )
    *v15 = 0;
  v4 = WdfFunctions.WdfRequestForwardToIoQueue(WdfDriverGlobals, Request, *(WDFQUEUE *)v7->gap60);
  if ( v4 < 0 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v13) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v13) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_03(v13, 0x27u, *(_DWORD *)&v7->field_0, *(_DWORD *)&v7->field_0, v4);
    }
    goto LABEL_22;
  }
}


// Function: EvtWdfDeviceFileCreate
void __fastcall EvtWdfDeviceFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
  unsigned int v5; // r3
  unsigned __int64 v6; // r0
  NTSTATUS v7; // r5
  unsigned int v8; // r3
  unsigned __int64 v9; // r0
  unsigned __int64 v10; // r0
  unsigned int v11; // r3
  unsigned __int64 v12; // r0
  unsigned int v13; // r3
  unsigned __int64 v14; // r0
  unsigned int v15; // r3
  unsigned __int64 v16; // r0
  unsigned int v17; // r3
  unsigned __int64 v18; // r0
  unsigned int v19; // r3
  unsigned __int64 v20; // r0
  unsigned int v21; // r3
  unsigned __int64 v22; // r0
  unsigned int v23; // r3
  unsigned __int64 v24; // r0
  unsigned int v25; // r3
  unsigned __int64 v26; // r0
  unsigned int v27; // r3
  unsigned __int64 v28; // r0
  unsigned int v29; // r3
  unsigned __int64 v30; // r0
  SMD_WORK_ITEM_CONTEXT *v31; // r0
  unsigned __int64 v32; // r0
  unsigned int v33; // r3
  unsigned __int64 v34; // r0
  SMD_WORK_ITEM_CONTEXT *v35; // r0
  unsigned __int64 v36; // r0
  unsigned int v37; // r3
  unsigned __int64 v38; // r0
  SMD_WORK_ITEM_CONTEXT *v39; // r0
  unsigned __int64 v40; // r0
  unsigned int v41; // r3
  unsigned __int64 v42; // r0
  SMD_WORK_ITEM_CONTEXT *v43; // r0
  unsigned __int64 v44; // r0
  int v46; // [sp+8h] [bp-90h] BYREF
  WDFREQUEST v47; // [sp+Ch] [bp-8Ch]
  int v48; // [sp+10h] [bp-88h] BYREF
  void *v49; // [sp+14h] [bp-84h]
  int v50; // [sp+18h] [bp-80h]
  int v51; // [sp+20h] [bp-78h] BYREF
  int v52; // [sp+24h] [bp-74h]
  int v53; // [sp+28h] [bp-70h]
  int v54; // [sp+2Ch] [bp-6Ch]
  int v55; // [sp+30h] [bp-68h]
  WDFFILEOBJECT v56; // [sp+34h] [bp-64h]
  int v57; // [sp+38h] [bp-60h]
  PVOID UniqueType; // [sp+3Ch] [bp-5Ch]
  _WDF_IO_QUEUE_CONFIG Config; // [sp+40h] [bp-58h] BYREF

  v46 = 0;
  v47 = Request;
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 )
  {
    v5 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v5 >= 4 )
    {
      HIDWORD(v6) = *((_DWORD *)off_40F178 + 5);
      LODWORD(v6) = *((_DWORD *)off_40F178 + 4);
      DoTraceMessage_03(v6, 0xADu, v5, Device, FileObject);
    }
  }
  v52 = 0;
  v53 = 0;
  v56 = 0;
  v57 = 0;
  v51 = 32;
  v54 = 1;
  v55 = 1;
  UniqueType = WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType;
  v7 = WdfFunctions.WdfObjectAllocateContext(
         WdfDriverGlobals,
         FileObject,
         (_WDF_OBJECT_ATTRIBUTES *)&v51,
         (PVOID *)&v46);
  if ( v7 >= 0 )
  {
    if ( v46 )
    {
      *(_DWORD *)v46 = 0;
      *(_DWORD *)(v46 + 4) = 0;
      *(_DWORD *)(v46 + 8) = 0;
      *(_DWORD *)(v46 + 12) = 0;
      *(_DWORD *)(v46 + 16) = 0;
      *(_DWORD *)(v46 + 20) = 0;
      *(_DWORD *)(v46 + 88) = 0;
      *(_DWORD *)(v46 + 92) = 0;
      *(_DWORD *)(v46 + 76) = 0;
      *(_DWORD *)(v46 + 80) = 0;
      *(_DWORD *)(v46 + 84) = 0;
      *(_DWORD *)(v46 + 196) = 0;
      *(_DWORD *)(v46 + 204) = 0;
      *(_DWORD *)(v46 + 200) = 0;
      *(_DWORD *)(v46 + 208) = 0;
      *(_DWORD *)(v46 + 148) = 0;
      *(_DWORD *)(v46 + 152) = 0;
      *(_DWORD *)(v46 + 156) = 0;
      *(_DWORD *)(v46 + 160) = 0;
      *(_DWORD *)(v46 + 164) = 0;
      *(_DWORD *)(v46 + 172) = 0;
      *(_DWORD *)(v46 + 176) = 0;
      *(_DWORD *)(v46 + 180) = 0;
      *(_DWORD *)(v46 + 184) = 0;
      *(_DWORD *)(v46 + 188) = 0;
      KeInitializeEvent((_KEVENT *)(v46 + 24), SynchronizationEvent, 0);
      KeInitializeEvent((_KEVENT *)(v46 + 40), SynchronizationEvent, 0);
      KeInitializeEvent((_KEVENT *)(v46 + 56), NotificationEvent, 1u);
      v52 = 0;
      v53 = 0;
      v57 = 0;
      UniqueType = 0;
      v51 = 32;
      v54 = 1;
      v55 = 1;
      v56 = FileObject;
      v7 = WdfFunctions.WdfSpinLockCreate(WdfDriverGlobals, (_WDF_OBJECT_ATTRIBUTES *)&v51, (WDFSPINLOCK *)(v46 + 132));
      if ( v7 >= 0 )
      {
        v52 = 0;
        v53 = 0;
        v57 = 0;
        UniqueType = 0;
        v51 = 32;
        v54 = 1;
        v55 = 1;
        v56 = FileObject;
        v7 = WdfFunctions.WdfWaitLockCreate(
               WdfDriverGlobals,
               (_WDF_OBJECT_ATTRIBUTES *)&v51,
               (WDFWAITLOCK *)(v46 + 136));
        if ( v7 >= 0 )
        {
          v52 = 0;
          v53 = 0;
          v57 = 0;
          UniqueType = 0;
          v51 = 32;
          v54 = 1;
          v55 = 1;
          v56 = FileObject;
          v7 = WdfFunctions.WdfWaitLockCreate(
                 WdfDriverGlobals,
                 (_WDF_OBJECT_ATTRIBUTES *)&v51,
                 (WDFWAITLOCK *)(v46 + 140));
          if ( v7 >= 0 )
          {
            v52 = 0;
            v53 = 0;
            v57 = 0;
            UniqueType = 0;
            v51 = 32;
            v54 = 1;
            v55 = 1;
            v56 = FileObject;
            v7 = WdfFunctions.WdfWaitLockCreate(
                   WdfDriverGlobals,
                   (_WDF_OBJECT_ATTRIBUTES *)&v51,
                   (WDFWAITLOCK *)(v46 + 144));
            if ( v7 >= 0 )
            {
              v52 = 0;
              v53 = 0;
              v57 = 0;
              UniqueType = 0;
              v51 = 32;
              v55 = 1;
              v54 = 2;
              *(_DWORD *)&Config.AllowZeroLengthRequests = 1;
              Config.EvtIoDefault = 0;
              Config.EvtIoDeviceControl = 0;
              memset(&Config.EvtIoStop, 0, 20);
              Config.Size = 56;
              Config.DispatchType = WdfIoQueueDispatchSequential;
              Config.EvtIoRead = EvtWdfIoQueueIoRead;
              Config.EvtIoWrite = EvtWdfIoQueueIoWrite;
              v56 = FileObject;
              Config.EvtIoInternalDeviceControl = EvtWdfIoQueueIoInternalDeviceControl;
              Config.PowerManaged = WdfFalse;
              v7 = WdfFunctions.WdfIoQueueCreate(
                     WdfDriverGlobals,
                     Device,
                     &Config,
                     (_WDF_OBJECT_ATTRIBUTES *)&v51,
                     (WDFQUEUE *)(v46 + 96));
              if ( v7 >= 0 )
              {
                v52 = 0;
                v53 = 0;
                v57 = 0;
                UniqueType = 0;
                v51 = 32;
                v54 = 1;
                v55 = 1;
                *(_DWORD *)&Config.AllowZeroLengthRequests = 1;
                memset(&Config.EvtIoDefault, 0, 20);
                Config.EvtIoResume = 0;
                Config.Settings.Parallel.NumberOfPresentedRequests = 0;
                Config.Driver = 0;
                Config.Size = 56;
                Config.DispatchType = WdfIoQueueDispatchManual;
                Config.EvtIoStop = EvtWdfIoQueueIoStop;
                Config.EvtIoCanceledOnQueue = EvtWdfIoQueueIoCanceledOnQueue;
                Config.PowerManaged = WdfFalse;
                v56 = FileObject;
                v7 = WdfFunctions.WdfIoQueueCreate(
                       WdfDriverGlobals,
                       Device,
                       &Config,
                       (_WDF_OBJECT_ATTRIBUTES *)&v51,
                       (WDFQUEUE *)(v46 + 100));
                if ( v7 >= 0 )
                {
                  v52 = 0;
                  v53 = 0;
                  v57 = 0;
                  UniqueType = 0;
                  v51 = 32;
                  v54 = 1;
                  v55 = 1;
                  *(_DWORD *)&Config.AllowZeroLengthRequests = 1;
                  memset(&Config.EvtIoDefault, 0, 20);
                  Config.EvtIoResume = 0;
                  Config.Settings.Parallel.NumberOfPresentedRequests = 0;
                  Config.Driver = 0;
                  Config.Size = 56;
                  Config.DispatchType = WdfIoQueueDispatchManual;
                  Config.EvtIoStop = EvtWdfIoQueueIoStop;
                  Config.EvtIoCanceledOnQueue = EvtWdfIoQueueIoCanceledOnQueue;
                  Config.PowerManaged = WdfFalse;
                  v56 = FileObject;
                  v7 = WdfFunctions.WdfIoQueueCreate(
                         WdfDriverGlobals,
                         Device,
                         &Config,
                         (_WDF_OBJECT_ATTRIBUTES *)&v51,
                         (WDFQUEUE *)(v46 + 104));
                  if ( v7 >= 0 )
                  {
                    v52 = 0;
                    v53 = 0;
                    v57 = 0;
                    UniqueType = 0;
                    v51 = 32;
                    v54 = 1;
                    v55 = 1;
                    *(_DWORD *)&Config.AllowZeroLengthRequests = 1;
                    memset(&Config.EvtIoDefault, 0, 20);
                    Config.EvtIoResume = 0;
                    Config.Settings.Parallel.NumberOfPresentedRequests = 0;
                    Config.Driver = 0;
                    Config.Size = 56;
                    Config.DispatchType = WdfIoQueueDispatchManual;
                    Config.EvtIoStop = EvtWdfIoQueueIoStop;
                    Config.EvtIoCanceledOnQueue = EvtWdfIoQueueIoCanceledOnQueue;
                    Config.PowerManaged = WdfFalse;
                    v56 = FileObject;
                    v7 = WdfFunctions.WdfIoQueueCreate(
                           WdfDriverGlobals,
                           Device,
                           &Config,
                           (_WDF_OBJECT_ATTRIBUTES *)&v51,
                           (WDFQUEUE *)(v46 + 108));
                    if ( v7 >= 0 )
                    {
                      v52 = 0;
                      v53 = 0;
                      v57 = 0;
                      UniqueType = 0;
                      v51 = 32;
                      v54 = 1;
                      v55 = 1;
                      *(_DWORD *)&Config.AllowZeroLengthRequests = 1;
                      memset(&Config.EvtIoDefault, 0, 20);
                      Config.EvtIoResume = 0;
                      Config.Settings.Parallel.NumberOfPresentedRequests = 0;
                      Config.Driver = 0;
                      Config.Size = 56;
                      Config.DispatchType = WdfIoQueueDispatchManual;
                      Config.EvtIoStop = EvtWdfIoQueueIoStop;
                      Config.EvtIoCanceledOnQueue = EvtWdfIoQueueIoCanceledOnQueue;
                      Config.PowerManaged = WdfFalse;
                      v56 = FileObject;
                      v7 = WdfFunctions.WdfIoQueueCreate(
                             WdfDriverGlobals,
                             Device,
                             &Config,
                             (_WDF_OBJECT_ATTRIBUTES *)&v51,
                             (WDFQUEUE *)(v46 + 112));
                      if ( v7 >= 0 )
                      {
                        v50 = 0;
                        v48 = 12;
                        v49 = SmdProcessIoReadRequestsWorkItem;
                        v52 = 0;
                        v53 = 0;
                        v57 = 0;
                        v51 = 32;
                        v54 = 1;
                        v55 = 1;
                        UniqueType = WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType;
                        v56 = FileObject;
                        v7 = WdfFunctions.WdfWorkItemCreate(
                               WdfDriverGlobals,
                               (_WDF_WORKITEM_CONFIG *)&v48,
                               (_WDF_OBJECT_ATTRIBUTES *)&v51,
                               (WDFWORKITEM *)(v46 + 116));
                        if ( v7 >= 0 )
                        {
                          v31 = (SMD_WORK_ITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                                           WdfDriverGlobals,
                                                           *(_DWORD *)(v46 + 116),
                                                           WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
                          if ( v31 )
                          {
                            *v31 = (SMD_WORK_ITEM_CONTEXT)FileObject;
                            v50 = 0;
                            v48 = 12;
                            v49 = SmdProcessIoRequestsWorkItem;
                            v52 = 0;
                            v53 = 0;
                            v57 = 0;
                            v51 = 32;
                            v54 = 1;
                            v55 = 1;
                            UniqueType = WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType;
                            v56 = FileObject;
                            v7 = WdfFunctions.WdfWorkItemCreate(
                                   WdfDriverGlobals,
                                   (_WDF_WORKITEM_CONFIG *)&v48,
                                   (_WDF_OBJECT_ATTRIBUTES *)&v51,
                                   (WDFWORKITEM *)(v46 + 120));
                            if ( v7 >= 0 )
                            {
                              v35 = (SMD_WORK_ITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                                               WdfDriverGlobals,
                                                               *(_DWORD *)(v46 + 120),
                                                               WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
                              if ( v35 )
                              {
                                *v35 = (SMD_WORK_ITEM_CONTEXT)FileObject;
                                v50 = 0;
                                v48 = 12;
                                v49 = SmdCompletePendingReadRequestsWorkItem;
                                v52 = 0;
                                v53 = 0;
                                v57 = 0;
                                v51 = 32;
                                v54 = 1;
                                v55 = 1;
                                UniqueType = WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType;
                                v56 = FileObject;
                                v7 = WdfFunctions.WdfWorkItemCreate(
                                       WdfDriverGlobals,
                                       (_WDF_WORKITEM_CONFIG *)&v48,
                                       (_WDF_OBJECT_ATTRIBUTES *)&v51,
                                       (WDFWORKITEM *)(v46 + 124));
                                if ( v7 >= 0 )
                                {
                                  v39 = (SMD_WORK_ITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                                                   WdfDriverGlobals,
                                                                   *(_DWORD *)(v46 + 124),
                                                                   WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
                                  if ( v39 )
                                  {
                                    *v39 = (SMD_WORK_ITEM_CONTEXT)FileObject;
                                    v50 = 0;
                                    v48 = 12;
                                    v49 = SmdCompletePendingWriteRequestsWorkItem;
                                    v52 = 0;
                                    v53 = 0;
                                    v57 = 0;
                                    v51 = 32;
                                    v54 = 1;
                                    v55 = 1;
                                    UniqueType = WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType;
                                    v56 = FileObject;
                                    v7 = WdfFunctions.WdfWorkItemCreate(
                                           WdfDriverGlobals,
                                           (_WDF_WORKITEM_CONFIG *)&v48,
                                           (_WDF_OBJECT_ATTRIBUTES *)&v51,
                                           (WDFWORKITEM *)(v46 + 128));
                                    if ( v7 >= 0 )
                                    {
                                      v43 = (SMD_WORK_ITEM_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                                                                       WdfDriverGlobals,
                                                                       *(_DWORD *)(v46 + 128),
                                                                       WDF_SMD_WORK_ITEM_CONTEXT_TYPE_INFO.UniqueType);
                                      if ( v43 )
                                      {
                                        *v43 = (SMD_WORK_ITEM_CONTEXT)FileObject;
                                        WdfFunctions.WdfObjectReferenceActual(
                                          WdfDriverGlobals,
                                          FileObject,
                                          0,
                                          3707,
                                          ".\\wdf\\driver.c");
                                      }
                                      else
                                      {
                                        v7 = -1073741435;
                                        if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0
                                          && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                                        {
                                          LODWORD(v44) = *((_DWORD *)off_40F178 + 4);
                                          HIDWORD(v44) = *((_DWORD *)off_40F178 + 5);
                                          DoTraceMessage_01(v44, 0xC0u);
                                          WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, -1073741435);
                                          return;
                                        }
                                      }
                                    }
                                    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                                    {
                                      v41 = *((unsigned __int8 *)off_40F178 + 29);
                                      if ( v41 >= 2 )
                                      {
                                        LODWORD(v42) = *((_DWORD *)off_40F178 + 4);
                                        HIDWORD(v42) = *((_DWORD *)off_40F178 + 5);
                                        DoTraceMessage_02(v42, 0xBFu, v41, v7);
                                        WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                                        return;
                                      }
                                    }
                                  }
                                  else
                                  {
                                    v7 = -1073741435;
                                    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0
                                      && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                                    {
                                      LODWORD(v40) = *((_DWORD *)off_40F178 + 4);
                                      HIDWORD(v40) = *((_DWORD *)off_40F178 + 5);
                                      DoTraceMessage_01(v40, 0xBEu);
                                      WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, -1073741435);
                                      return;
                                    }
                                  }
                                }
                                else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                                {
                                  v37 = *((unsigned __int8 *)off_40F178 + 29);
                                  if ( v37 >= 2 )
                                  {
                                    LODWORD(v38) = *((_DWORD *)off_40F178 + 4);
                                    HIDWORD(v38) = *((_DWORD *)off_40F178 + 5);
                                    DoTraceMessage_02(v38, 0xBDu, v37, v7);
                                    WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                                    return;
                                  }
                                }
                              }
                              else
                              {
                                v7 = -1073741435;
                                if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0
                                  && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                                {
                                  LODWORD(v36) = *((_DWORD *)off_40F178 + 4);
                                  HIDWORD(v36) = *((_DWORD *)off_40F178 + 5);
                                  DoTraceMessage_01(v36, 0xBCu);
                                  WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, -1073741435);
                                  return;
                                }
                              }
                            }
                            else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                            {
                              v33 = *((unsigned __int8 *)off_40F178 + 29);
                              if ( v33 >= 2 )
                              {
                                LODWORD(v34) = *((_DWORD *)off_40F178 + 4);
                                HIDWORD(v34) = *((_DWORD *)off_40F178 + 5);
                                DoTraceMessage_02(v34, 0xBBu, v33, v7);
                                WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                                return;
                              }
                            }
                          }
                          else
                          {
                            v7 = -1073741435;
                            if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
                            {
                              LODWORD(v32) = *((_DWORD *)off_40F178 + 4);
                              HIDWORD(v32) = *((_DWORD *)off_40F178 + 5);
                              DoTraceMessage_01(v32, 0xBAu);
                              WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, -1073741435);
                              return;
                            }
                          }
                        }
                        else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                        {
                          v29 = *((unsigned __int8 *)off_40F178 + 29);
                          if ( v29 >= 2 )
                          {
                            LODWORD(v30) = *((_DWORD *)off_40F178 + 4);
                            HIDWORD(v30) = *((_DWORD *)off_40F178 + 5);
                            DoTraceMessage_02(v30, 0xB9u, v29, v7);
                            WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                            return;
                          }
                        }
                      }
                      else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                      {
                        v27 = *((unsigned __int8 *)off_40F178 + 29);
                        if ( v27 >= 2 )
                        {
                          LODWORD(v28) = *((_DWORD *)off_40F178 + 4);
                          HIDWORD(v28) = *((_DWORD *)off_40F178 + 5);
                          DoTraceMessage_02(v28, 0xB8u, v27, v7);
                          WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                          return;
                        }
                      }
                    }
                    else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                    {
                      v25 = *((unsigned __int8 *)off_40F178 + 29);
                      if ( v25 >= 2 )
                      {
                        LODWORD(v26) = *((_DWORD *)off_40F178 + 4);
                        HIDWORD(v26) = *((_DWORD *)off_40F178 + 5);
                        DoTraceMessage_02(v26, 0xB7u, v25, v7);
                        WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                        return;
                      }
                    }
                  }
                  else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                  {
                    v23 = *((unsigned __int8 *)off_40F178 + 29);
                    if ( v23 >= 2 )
                    {
                      LODWORD(v24) = *((_DWORD *)off_40F178 + 4);
                      HIDWORD(v24) = *((_DWORD *)off_40F178 + 5);
                      DoTraceMessage_02(v24, 0xB6u, v23, v7);
                      WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                      return;
                    }
                  }
                }
                else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
                {
                  v21 = *((unsigned __int8 *)off_40F178 + 29);
                  if ( v21 >= 2 )
                  {
                    LODWORD(v22) = *((_DWORD *)off_40F178 + 4);
                    HIDWORD(v22) = *((_DWORD *)off_40F178 + 5);
                    DoTraceMessage_02(v22, 0xB5u, v21, v7);
                    WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                    return;
                  }
                }
              }
              else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
              {
                v19 = *((unsigned __int8 *)off_40F178 + 29);
                if ( v19 >= 2 )
                {
                  LODWORD(v20) = *((_DWORD *)off_40F178 + 4);
                  HIDWORD(v20) = *((_DWORD *)off_40F178 + 5);
                  DoTraceMessage_02(v20, 0xB4u, v19, v7);
                  WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                  return;
                }
              }
            }
            else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
            {
              v17 = *((unsigned __int8 *)off_40F178 + 29);
              if ( v17 >= 2 )
              {
                LODWORD(v18) = *((_DWORD *)off_40F178 + 4);
                HIDWORD(v18) = *((_DWORD *)off_40F178 + 5);
                DoTraceMessage_02(v18, 0xB3u, v17, v7);
                WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
                return;
              }
            }
          }
          else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
          {
            v15 = *((unsigned __int8 *)off_40F178 + 29);
            if ( v15 >= 2 )
            {
              LODWORD(v16) = *((_DWORD *)off_40F178 + 4);
              HIDWORD(v16) = *((_DWORD *)off_40F178 + 5);
              DoTraceMessage_02(v16, 0xB2u, v15, v7);
              WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
              return;
            }
          }
        }
        else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
        {
          v13 = *((unsigned __int8 *)off_40F178 + 29);
          if ( v13 >= 2 )
          {
            LODWORD(v14) = *((_DWORD *)off_40F178 + 4);
            HIDWORD(v14) = *((_DWORD *)off_40F178 + 5);
            DoTraceMessage_02(v14, 0xB1u, v13, v7);
            WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
            return;
          }
        }
      }
      else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
      {
        v11 = *((unsigned __int8 *)off_40F178 + 29);
        if ( v11 >= 2 )
        {
          LODWORD(v12) = *((_DWORD *)off_40F178 + 4);
          HIDWORD(v12) = *((_DWORD *)off_40F178 + 5);
          DoTraceMessage_02(v12, 0xB0u, v11, v7);
          WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
          return;
        }
      }
    }
    else
    {
      v7 = -1073741435;
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_01(v10, 0xAFu);
        WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, -1073741435);
        return;
      }
    }
  }
  else if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
  {
    v8 = *((unsigned __int8 *)off_40F178 + 29);
    if ( v8 >= 2 )
    {
      LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v9, 0xAEu, v8, v7);
      WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
      return;
    }
  }
  WdfFunctions.WdfRequestComplete(WdfDriverGlobals, v47, v7);
}


// Function: EvtWdfFileClose
void __fastcall EvtWdfFileClose(WDFFILEOBJECT FileObject)
{
  SMD_PORT_CONTEXT *v1; // r0
  SMD_PORT_CONTEXT *v2; // r5
  unsigned __int64 v3; // r0
  int v4; // r3
  unsigned __int64 v5; // r0
  WDFWAITLOCK v6; // r1
  int v7; // r0
  unsigned __int64 v8; // r0
  unsigned __int64 v9; // r0
  unsigned __int64 v10; // r0

  v1 = (SMD_PORT_CONTEXT *)WdfFunctions.WdfObjectGetTypedContextWorker(
                             WdfDriverGlobals,
                             FileObject,
                             WDF_SMD_PORT_CONTEXT_TYPE_INFO.UniqueType);
  v2 = v1;
  if ( !v1 )
  {
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
    {
      LODWORD(v3) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v3) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_01(v3, 0xC1u);
    }
    return;
  }
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    v4 = *(_DWORD *)&v1->field_0;
    LODWORD(v5) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v5) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_02(v5, 0xC2u, v4);
  }
  WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v2->field_90, 0);
  v6 = v2->field_90;
  v7 = WdfDriverGlobals;
  if ( *(_DWORD *)&v2->field_c4 )
  {
    *(_DWORD *)&v2->field_c4 = 0;
    WdfFunctions.WdfWaitLockRelease(v7, v6);
    WdfFunctions.WdfIoQueuePurgeSynchronously(WdfDriverGlobals, *(WDFQUEUE *)&v2->gap60[4]);
    WdfFunctions.WdfIoQueuePurgeSynchronously(WdfDriverGlobals, v2->field_68);
    WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v2->field_88, 0);
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v2->field_88);
    WdfFunctions.WdfWaitLockAcquire(WdfDriverGlobals, v2->field_8c, 0);
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v2->field_8c);
    if ( InterfaceFunction_01(*(SMD_PORT_CONTEXT **)&v2->field_0) < 0 )
    {
      if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 2u )
      {
        HIDWORD(v8) = *((_DWORD *)off_40F178 + 5);
        LODWORD(v8) = *((_DWORD *)off_40F178 + 4);
        DoTraceMessage_03(v8, 0xC3u, *(_DWORD *)&v2->field_0);
      }
      return;
    }
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 5u )
    {
      LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
      HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
      DoTraceMessage_02(v9, 0xC4u, *(_DWORD *)&v2->field_0, *(_DWORD *)&v2->field_0);
    }
  }
  else
  {
    WdfFunctions.WdfWaitLockRelease(WdfDriverGlobals, v6);
  }
  KeWaitForSingleObject(&v2->field_38, Executive, KernelMode, 1u, 0);
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
  {
    LODWORD(v10) = *((_DWORD *)off_40F178 + 4);
    HIDWORD(v10) = *((_DWORD *)off_40F178 + 5);
    DoTraceMessage_03(v10, 0xC5u, *(_DWORD *)&v2->field_0);
  }
}


// Function: DriverEntry
int __fastcall DriverEntry(_DRIVER_OBJECT *DriverObject, _UNICODE_STRING *RegistryPath)
{
  _DEVICE_OBJECT *TracingSupport; // r0
  const _UNICODE_STRING *v5; // r1
  int result; // r0
  int v7; // r4
  unsigned int v8; // r3
  unsigned __int64 v9; // r0
  _WDF_DRIVER_CONFIG DriverConfig; // [sp+10h] [bp-50h] BYREF
  _WDF_OBJECT_ATTRIBUTES DriverAttributes; // [sp+28h] [bp-38h] BYREF

  McGenEventRegister(
    &ETW_Provider_GUID_02,
    (void (__fastcall *)(const _GUID *, unsigned int, unsigned __int8, unsigned __int64, unsigned __int64, _EVENT_FILTER_DESCRIPTOR *, void *))RegistryPath,
    &ETW_CallbackContext_02,
    &ETW_RegistrationHandle_02);
  dword_415AA0 = 0;
  pETW_provider_GUID = (int)&ETW_Provider_GUID_03;
  dword_415AA8 = 0;
  dword_415AB8 = 0;
  byte_415ABC = 1;
  byte_415ABD = 0;
  word_415ABE = 0;
  dword_415AC0 = 0;
  TracingSupport = (_DEVICE_OBJECT *)WppLoadTracingSupport();
  dword_415AB8 = 0;
  WppInitKm(TracingSupport, v5);
  if ( (*((_DWORD *)off_40F178 + 8) & 1) != 0 && *((unsigned __int8 *)off_40F178 + 29) >= 4u )
    DoTraceMessage_06(*((_DWORD *)off_40F178 + 4), *((_DWORD *)off_40F178 + 5));
  DriverConfig.DriverInitFlags = 0;
  DriverConfig.DriverPoolTag = 0;
  DriverConfig.Size = 20;
  DriverConfig.EvtDriverDeviceAdd = SmdEvtDeviceAdd;
  DriverConfig.EvtDriverUnload = EvtDriverUnload;
  DriverAttributes.EvtCleanupCallback = 0;
  DriverAttributes.EvtDestroyCallback = 0;
  DriverAttributes.ParentObject = 0;
  DriverAttributes.ContextSizeOverride = 0;
  DriverAttributes.Size = 32;
  DriverAttributes.ExecutionLevel = WdfExecutionLevelInheritFromParent;
  DriverAttributes.SynchronizationScope = WdfSynchronizationScopeInheritFromParent;
  DriverAttributes.ContextTypeInfo = (_WDF_OBJECT_CONTEXT_TYPE_INFO *)WDF_SMD_DRIVER_CONTEXT_TYPE_INFO.UniqueType;
  result = WdfFunctions.WdfDriverCreate(
             WdfDriverGlobals,
             DriverObject,
             RegistryPath,
             &DriverAttributes,
             &DriverConfig,
             0);
  v7 = result;
  if ( result < 0 )
  {
    if ( dword_40FBB4 && byte_40FBB8 != 1 )
      EventWrite_02(
        ETW_RegistrationHandle_02,
        &stru_40E3B8,
        (const _GUID *)aDriverentry,
        aDriverentry,
        aWdfdrivercreat,
        result);
    if ( (*((_DWORD *)off_40F178 + 8) & 2) != 0 )
    {
      v8 = *((unsigned __int8 *)off_40F178 + 29);
      if ( v8 >= 2 )
      {
        LODWORD(v9) = *((_DWORD *)off_40F178 + 4);
        HIDWORD(v9) = *((_DWORD *)off_40F178 + 5);
        DoTraceMessage_02(v9, 0xCu, v8, v7);
      }
    }
    return v7;
  }
  return result;
}


// Function: __security_init_cookie
void _security_init_cookie()
{
  int *v0; // r1
  int v1; // r2
  unsigned int v2; // r3

  v0 = off_4191A0;
  v1 = dword_41919C;
  v2 = *off_4191A0;
  if ( !*off_4191A0 || v2 == dword_41919C )
  {
    v2 = **(_DWORD **)off_419198 ^ (unsigned int)off_4191A0;
    *off_4191A0 = v2;
    if ( !v2 )
    {
      v2 = v1;
      *v0 = v1;
    }
  }
  *off_419194 = ~v2;
}


