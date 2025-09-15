import ida_bytes
import ida_frame
import ida_funcs
import ida_kernwin
import ida_lines
import ida_hexrays
import ida_typeinf
import idaapi
import idc
import re
import uuid

action_SetGUID = "wp81:setGUID"
action_Set_wchar_t = "wp81:setwchar_t"

# class SetNtStatus(ida_kernwin.action_handler_t):
	# def __init__(self):
		# ida_kernwin.action_handler_t.__init__(self)
	
	# def activate(self, ctx):
		# vdui = ida_hexrays.get_widget_vdui(ctx.widget)
		# if vdui.get_current_item(ida_hexrays.USE_KEYBOARD) and vdui.item.is_citem():
			# ntstatus_tinfo = idaapi.tinfo_t()
			# ntstatus_tinfo.get_named_type(None, 'NTSTATUS')
			# value = vdui.get_number().value(ntstatus_tinfo)
			# print(f"value={hex(value)}")
			# vdui.set_num_radix(16)
			
			# print(f"address item={hex(vdui.item.get_ea())}")
			# print(f"address tail={hex(vdui.tail.get_ea())}")
			# print(f"line number={vdui.cpos.lnnum}")
			# print(f"possible comt type={vdui.calc_cmt_type(vdui.cpos.lnnum,ida_hexrays.CMT_TAIL)} CMT_NONE={ida_hexrays.CMT_NONE} CMT_TAIL={ida_hexrays.CMT_TAIL} CMT_ALL={ida_hexrays.CMT_ALL}")
			# tl = ida_hexrays.treeloc_t()
			# tl.ea = vdui.tail.get_ea()  # Set the address
			# tl.itp = ida_hexrays.ITP_SEMI
			# print(f"tail.loc.ea={hex(vdui.tail.loc.ea)}")
			# print(f"tail.loc.itp={vdui.tail.loc.itp} ITP_EMPTY={ida_hexrays.ITP_EMPTY} ITP_SEMI={ida_hexrays.ITP_SEMI} ITP_SIGN={ida_hexrays.ITP_SIGN}")
			# vdui.cfunc.set_user_cmt(vdui.tail.loc,"testFG")
			# vdui.refresh_ctext()
			# # https://hex-rays.com/blog/coordinate-system-for-hex-rays
			# # vdui_t.calc_cmt_type
		# return 1
	
	# def update(self, ctx):
		# result = ida_kernwin.AST_DISABLE
		# if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE and isFocusOnNumber(ctx):
			# result = ida_kernwin.AST_ENABLE
		# return result
class SetGUID(ida_kernwin.action_handler_t):
	def __init__(self):
		ida_kernwin.action_handler_t.__init__(self)
	
	def activate(self, ctx):
		current_type = idc.get_type(ctx.cur_ea)
		if current_type == None :
			GUID_tinfo = idaapi.tinfo_t()
			GUID_tinfo.get_named_type(None, "_GUID")
			if not ida_typeinf.apply_tinfo(ctx.cur_ea, GUID_tinfo, ida_typeinf.TINFO_STRICT):
				print(f"Failed: apply type '{GUID_tinfo}' at address {hex(ctx.cur_ea)}")
		if current_type != None and current_type != "GUID" and current_type != "_GUID":
			return 1
		GUID_bytes = idc.get_bytes(ctx.cur_ea, 16)
		new_uuid = uuid.UUID(bytes_le=GUID_bytes)
		GUID_str = f"{new_uuid}"
		current_comment = ida_bytes.get_cmt(ctx.cur_ea, False)
		if current_comment == None :
			ida_bytes.set_cmt(ctx.cur_ea, f"GUID {{{GUID_str}}}", False)
		elif not GUID_str in current_comment:
			ida_bytes.append_cmt(ctx.cur_ea, f"GUID {{{GUID_str}}}", False)
		return 1
	
	def update(self, ctx):
		result = ida_kernwin.AST_DISABLE
		if ctx.widget_type == ida_kernwin.BWN_DISASM and self.isSetGuidPossible(ctx):
			result = ida_kernwin.AST_ENABLE
		return result
	
	def isSetGuidPossible(self, ctx):
		result = False
		current_type = idc.get_type(ctx.cur_ea)
		if current_type == None or current_type == "GUID" or current_type == "_GUID":
			result = True
		return result

class Set_wchar_t(ida_kernwin.action_handler_t):
	def __init__(self):
		ida_kernwin.action_handler_t.__init__(self)
	
	def activate(self, ctx):
		vdui = ida_hexrays.get_widget_vdui(ctx.widget)
		if vdui.get_current_item(ida_hexrays.USE_KEYBOARD) and vdui.item.is_citem():
			wchar_t_tinfo = idaapi.tinfo_t()
			wchar_t_tinfo.get_named_type(None, "wchar_t")
			array_wchar_t_tinfo = idaapi.tinfo_t()
			array_wchar_t_tinfo.create_array(wchar_t_tinfo, 12, 0)
			print(f"{array_wchar_t_tinfo._print()}")
			print(f"is_correct={array_wchar_t_tinfo.is_correct()}")
			print(f"vdui.item.e={vdui.item.e}")
			print(f"vdui.item.e.type={vdui.item.e.type}")
			print(f"vdui.item.e.type.is_array()={vdui.item.e.type.is_array()}")
			print(f"vdui.item.e.type.get_array_nelems()={vdui.item.e.type.get_array_nelems()}")
			print(f"vdui.item.e.v.getv().is_stk_var()={vdui.item.e.v.getv().is_stk_var()}")
			#print(f"result={vdui.item.e.v.getv().set_lvar_type(array_wchar_t_tinfo, False)}") # may_fail=True
			print(f"vdui.item.get_ea()={hex(ctx.cur_ea)}")
			func = ida_funcs.get_func(ctx.cur_ea)
			print(f"func={func}")
			print(f"vdui.item.e.v.getv().name={vdui.item.e.v.getv().name}")
			print(f"vdui.item.e.v.getv().get_stkoff()={hex(vdui.item.e.v.getv().get_stkoff())}")
			print(f"vdui.cfunc.get_stkoff_delta()={hex(vdui.cfunc.get_stkoff_delta())}")
			print(f"vdui.item.e.v.location.stkoff()={hex(vdui.item.e.v.getv().location.stkoff())}")
			print(f"ida_frame.get_frame_size(func)={ida_frame.get_frame_size(func)}")
			print(f"result={ida_frame.set_frame_member_type(func, vdui.item.e.v.getv().get_stkoff()-0x168, array_wchar_t_tinfo)}")
		return 1
	
	def update(self, ctx):
		result = ida_kernwin.AST_DISABLE
		if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE and self.isFocusOnVariable(ctx):
			result = ida_kernwin.AST_ENABLE
		return result
	
	def isFocusOnVariable(self, ctx):
		result = False
		vdui = ida_hexrays.get_widget_vdui(ctx.widget)
		if vdui.get_current_item(ida_hexrays.USE_MOUSE) and vdui.item.is_citem():
			# vdui.item is a ctree_item_t, vdui.item.e is a cexpr_t, vdui.item.it is a citem_t
			citem = vdui.item.it
			if citem.is_expr() and citem.cexpr.op == idaapi.cot_var:
				result = True
		return result

class MyUIHooks(ida_kernwin.UI_Hooks):
	def __init__(self):
		ida_kernwin.UI_Hooks.__init__(self)
	
	def finish_populating_widget_popup(self, widget, popup):
		if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
			ida_kernwin.attach_action_to_popup(widget, popup, action_SetGUID, None)
		if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
			ida_kernwin.attach_action_to_popup(widget, popup, action_Set_wchar_t, None)

# class MyPseudocodeHooks(ida_hexrays.Hexrays_Hooks):
	# # def create_hint(self, vu):
		# # if vu.get_current_item(ida_hexrays.USE_MOUSE):
			# # if vu.item.citype == ida_hexrays.VDI_EXPR:
				# # cexpr = vu.item.e
				# # if cexpr.op == ida_hexrays.cot_num:
					# # return 0, "NTSTATUS?? ", 0 #0/1=continue/stop collecting hint, hint, number of important lines added
		# # return 0
	
	# def func_printed(self, cfunc):
		# nbLine = len(cfunc.get_pseudocode())
		# print(f"nbLines={nbLine}")
		# #self.debugSimpleLine(cfunc.get_pseudocode()[3])
		# idxLine = 0
		# while idxLine < nbLine:
			# simpleline = cfunc.get_pseudocode()[idxLine]
			# match = re.search(r' (-?\d{10})', ida_lines.tag_remove(simpleline.line))
			# if match:
				# strFound = match.group(1)
				# valueFound = int(strFound)
				# if valueFound < 0 :
					# valueFound = valueFound & 0xFFFFFFFF # get unsigned value
				# #print(f"line {idxLine+1:04} found {hex(valueFound)} {ntstatus_dict.get(valueFound)}")
				# newStrValue = f"{ntstatus_dict.get(valueFound)}_{valueFound:08X}"
				# simpleline.line = simpleline.line.replace(strFound, newStrValue)
			# idxLine += 1
		# #cfunc.get_pseudocode()[2].line += f" {ida_lines.COLOR_ON}{ida_lines.SCOLOR_SYMBOL}//{ida_lines.COLOR_OFF}{ida_lines.SCOLOR_SYMBOL} {ida_lines.COLOR_ON}{ida_lines.SCOLOR_NUMBER}TESTFG{ida_lines.COLOR_OFF}{ida_lines.SCOLOR_NUMBER}"
		
		# return 0  # Return 0 to allow IDA to display the modified text ?
	
	# def debugSimpleLine(self, simpleline):
		# print(f"type={type(simpleline)}") # ida_kernwin.simpleline_t
		# print(f"type={type(simpleline.line)} line={ida_lines.tag_remove(simpleline.line)}") # str
		# print(f"type={type(simpleline.color)} color={simpleline.color}") # uchar
		# print(f"type={type(simpleline.bgcolor)} bgcolor={hex(simpleline.bgcolor)}") # int32 BGR
		# for char in simpleline.line:
			# if ord(char) >= 32 :
				# print(f" '{char}' ", end="")
			# else:
				# print(f" '.' ", end="")
		# print("")
		# for char in simpleline.line:
			# print(f"0x{ord(char):02x} ", end="")		
		# print("")

def create_UI_hooks():
	return MyUIHooks()

# def create_Pseudocode_hooks():
	# return MyPseudocodeHooks()

def create_actions():
	action_desc = ida_kernwin.action_desc_t(
		action_SetGUID,	# Name. Acts as an ID. Must be unique.
		"Set GUID",		# Label. That's what users see.
		SetGUID())
	if not ida_kernwin.register_action(action_desc):
		print(f"Failed to register action {action_SetGUID}")
		
	action_desc = ida_kernwin.action_desc_t(
		action_Set_wchar_t,	# Name. Acts as an ID. Must be unique.
		"Set wchar_t",		# Label. That's what users see.
		Set_wchar_t())
	if not ida_kernwin.register_action(action_desc):
		print(f"Failed to register action {action_Set_wchar_t}")


# def isFocusOnNumber(ctx):
	# result = False
	# vdui = ida_hexrays.get_widget_vdui(ctx.widget)
	# if vdui.get_current_item(ida_hexrays.USE_MOUSE) and vdui.item.is_citem():
		# # vdui.item is a ctree_item_t, vdui.item.e is a cexpr_t, vdui.item.it is a citem_t
		# citem = vdui.item.it
		# if citem.is_expr() and citem.cexpr.op == idaapi.cot_num:
			# result = True
	# return result