# A simple plugin for IDA Pro
# This plugin will display a message box when loaded from the Plugins menu.

# Import the necessary IDA Python modules
import ida_idaapi
import ida_kernwin
import traceback

from wp81IdaDriverAnalyzer import wdf
from wp81IdaDriverAnalyzer import ui

# The main plugin class. It must inherit from ida_idaapi.plugin_t
class Wp81IdaDriverAnalyzerPlugin(ida_idaapi.plugin_t):
	# Keep the plugin in memory after execution ('run' function) in order to keep the 'hooks' active
	flags = ida_idaapi.PLUGIN_KEEP
	
	# A brief comment about the plugin
	comment = "Assist reverse engineering of Windows Phone 8.1 drivers"
	
	# The name of the plugin that will appear in the Plugins menu
	wanted_name = "Wp81 Driver Analyzer"
	
	# An optional hotkey to run the plugin
	wanted_hotkey = "Ctrl-Shift-H"

	def init(self):
		"""
		This method is called when the plugin is loaded by IDA.
		It should return PLUGIN_OK if the plugin is ready to be used,
		or PLUGIN_SKIP if the plugin should not be loaded.
		"""
		# Print a message to IDA's Output window to confirm loading
		print("Wp81 Driver Analyzer: Init called.")
		
		ui.create_actions()
		
		# Keep a reference to the Hooks objects to avoid garbage collection
		self.UI_hooks = ui.create_UI_hooks()
		self.UI_hooks.hook()
		
		# Returns PLUGIN_KEEP to keep the plugin in memory.
		return ida_idaapi.PLUGIN_KEEP

	def run(self, arg):
		"""
		This method is called when the user runs the plugin from the menu
		or with the hotkey. This is where the main functionality lives.
		"""
		print("Wp81 Driver Analyzer: Run called.")
		try:
			ida_kernwin.show_wait_box("HIDECANCEL\nWp81 Driver Analyzer: Analyzing")
			
			wdf.add_enums()
			wdf.add_structures()
			wdf.rename_functions_and_offsets()
			
			print("Wp81 Driver Analyzer: finished.")
		except Exception as e:
			# Handle the error gracefully
			print(f"Wp81 Driver Analyzer: An error occurred: {e}")
			traceback.print_exc()
		finally:
			# This code will always execute, whether there was an error or not
			# Hide the wait box
			ida_kernwin.hide_wait_box()

	def term(self):
		"""
		This method is called when the plugin is unloaded.
		It should be used for any cleanup or teardown tasks.
		"""
		print("Wp81 Driver Analyzer: Term called.")
		# No cleanup is needed for this simple plugin.
		


# The entry point for the plugin.
# This function is what IDA will call to get a new instance of our plugin class.
def PLUGIN_ENTRY():
	return Wp81IdaDriverAnalyzerPlugin()
