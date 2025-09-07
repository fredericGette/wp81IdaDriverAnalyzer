import ida_kernwin
import ida_lines
import ida_hexrays
import idaapi

action_setNtStatus = "wp81:set_nt_status"

class SetNtStatus(ida_kernwin.action_handler_t):
	def __init__(self):
		ida_kernwin.action_handler_t.__init__(self)

	def activate(self, ctx):
		vdui = ida_hexrays.get_widget_vdui(ctx.widget)
		if vdui.get_current_item(ida_hexrays.USE_KEYBOARD) and vdui.item.is_citem():
			ntstatus_tinfo = idaapi.tinfo_t()
			ntstatus_tinfo.get_named_type(None, 'NTSTATUS')
			value = vdui.get_number().value(ntstatus_tinfo)
			print(f"value={hex(value)}")
			vdui.set_num_radix(16)
			tl = ida_hexrays.treeloc_t()
			tl.ea = vdui.item.get_ea()  # Set the address
			tl.itp = ida_hexrays.ITP_SEMI
			vdui.cfunc.set_user_cmt(tl,"testFG")
		return 1

	def update(self, ctx):
		result = ida_kernwin.AST_DISABLE
		if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE and isFocusOnNumber(ctx):
			result = ida_kernwin.AST_ENABLE
		return result

class MyUIHooks(ida_kernwin.UI_Hooks):
	def __init__(self):
		ida_kernwin.UI_Hooks.__init__(self)

	def finish_populating_widget_popup(self, widget, popup):
		if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
			ida_kernwin.attach_action_to_popup(widget, popup, action_setNtStatus, None)

class MyHintHooks(ida_hexrays.Hexrays_Hooks):
	def create_hint(self, vu):
		if vu.get_current_item(ida_hexrays.USE_MOUSE):
			if vu.item.citype == ida_hexrays.VDI_EXPR:
				cexpr = vu.item.e
				if cexpr.op == ida_hexrays.cot_num:
					return 0, "NTSTATUS?? ", 0 #0/1=continue/stop collecting hint, hint, number of important lines added
		return 0

	def func_printed(self, cfunc):
		print(f"type={type(cfunc.get_pseudocode())}") # ida_pro.strvec_t
		print(f"type={type(cfunc.get_pseudocode()[0])}") # ida_kernwin.simpleline_t
		print(f"type={type(cfunc.get_pseudocode()[0].line)}") # str
		print(f"type={type(cfunc.get_pseudocode()[0].color)}") # uchar
		print(f"type={type(cfunc.get_pseudocode()[0].bgcolor)}") # int32 BGR
		print(f"line={ida_lines.tag_remove(cfunc.get_pseudocode()[2].line)}")
		print(f"line={str(cfunc.get_pseudocode()[2].line)}")
		print("original:")
		for char in cfunc.get_pseudocode()[3].line:
			print(f"'{char}': {ord(char):04x}")
		cfunc.get_pseudocode()[2].line += f" {ida_lines.COLOR_ON}{ida_lines.SCOLOR_SYMBOL}//{ida_lines.COLOR_OFF}{ida_lines.SCOLOR_SYMBOL} {ida_lines.COLOR_ON}{ida_lines.SCOLOR_NUMBER}TESTFG{ida_lines.COLOR_OFF}{ida_lines.SCOLOR_NUMBER}"
		print("updated:")
		for char in cfunc.get_pseudocode()[2].line:
			print(f"'{char}': {ord(char):04x}")
		return 0  # Return 0 to allow IDA to display the modified text ?

def create_UI_hooks():
	return MyUIHooks()

def create_Hint_hooks():
	return MyHintHooks()

def create_actions():
	action_desc = ida_kernwin.action_desc_t(
		action_setNtStatus,	# Name. Acts as an ID. Must be unique.
		"Set NTSTATUS",		# Label. That's what users see.
		SetNtStatus())
	if not ida_kernwin.register_action(action_desc):
		print(f"Failed to register action {action_setNtStatus}")


def isFocusOnNumber(ctx):
	result = False
	vdui = ida_hexrays.get_widget_vdui(ctx.widget)
	if vdui.get_current_item(ida_hexrays.USE_MOUSE) and vdui.item.is_citem():
		# vdui.item is a ctree_item_t, vdui.item.e is a cexpr_t, vdui.item.it is a citem_t
		citem = vdui.item.it
		if citem.is_expr() and citem.cexpr.op == idaapi.cot_num:
			result = True
	return result