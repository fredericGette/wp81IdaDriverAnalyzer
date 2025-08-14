# A simple "Hello, World" style plugin for IDA Pro
# This plugin will display a message box when loaded from the Plugins menu.

# Import the necessary IDA Python modules
import ida_idaapi
import ida_kernwin

from wp81IdaDriverAnalyzer import wdf

# The main plugin class. It must inherit from ida_idaapi.plugin_t
class Wp81IdaDriverAnalyzerPlugin(ida_idaapi.plugin_t):
	# Plugin flags. PLUGIN_UNL means the plugin can be unloaded.
	# PLUGIN_MULTI means multiple instances of the plugin can be loaded.
	flags = ida_idaapi.PLUGIN_UNL
	
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
		
		# We can add checks here, e.g., if a database is open.
		# For this simple plugin, we always return PLUGIN_OK.
		return ida_idaapi.PLUGIN_OK

	def run(self, arg):
		"""
		This method is called when the user runs the plugin from the menu
		or with the hotkey. This is where the main functionality lives.
		"""
		print("Wp81 Driver Analyzer: Run called.")
		wdf.add_WDFFUNCTIONS_structure()
		wdf.add_parameters_structures()
		wdf.rename_wdf_functions()
		
		# Display a simple message box to the user
		ida_kernwin.info("Analyze finished!")

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
