from winappdbg import *
from winappdbg.win32 import *
import sys
import ctypes
import time
import _winreg
import os 
from subprocess import Popen, PIPE

#EventHandler
class MyEventHandler( EventHandler ):

    #Tell WinAppDbg which functions we want to hook with the apiHooks property
    apiHooks = {
        #Broken up per dll
        "kernel32.dll":[
            ("IsDebuggerPresent",0),
            #New kernel32.dll function added with a single parameter
            ("CloseHandle",1),
			("GetTickCount",0)
        ]
    }

	#CREATE_PROCESS_DEBUG_EVENT handler
    def create_process( self, event ):
        print "Process created!"
        
        print "TID"
        print event.get_tid()

        #Get the process object
        process = event.get_process()
        
        #Get the main_module object
        main_module = process.get_main_module()
        
        #Display the virtual address base the exe was loaded at
        print "Main Module Loaded at: %08x" % main_module.get_base()
        
        #Get the address of the PEB
        peb = process.get_peb_address()
        #Check if the BeingDebugged Flag is set
        #The \x is an escape sequence that tells Python to handle the
        #next two characters as hexadecimal characters
        if process.peek(peb+2,1) == '\x01':
            print "BeingDebugged flag is True!"
            print "Setting BeingDebugged flag to False"
            #Attempt to clear the BeingDebugged Flag
            try:
                process.poke(peb+2,'\x00')
                #Validate that the Flag has been cleared
                if process.peek(peb+2,1) == '\x00':
                    print "BeingDebugged flag successfully cleared!"
            except:
                print "ERROR!: Failed to clear BeingDebugged flag"

	#post-callback function for IsDebuggerPresent()
    #called immediately before returning from the API call
    def post_IsDebuggerPresent(self,event,retval):
        print "IsDebuggerPresent() called!"
        print "Returning False!"
        
        #Get the thread that made the API call
        thread = event.get_thread()
        
        #Set the register containing the return value, EAX, to 0               
        thread.set_register("Eax",0x0)
		
    #pre callback function for CloseHandle()
    #the handle parameter is the actual parameter for CloseHandle
    def pre_CloseHandle( self, event, return_address, handle ):     
        print "CloseHandle() called..."
        
        # get process object 
        process = event.get_process()
        
        #get thread object
        thread = event.get_thread()
        
        #get cpu value context for thread
        registers = thread.get_context()
        
        #get the current value of the Esp register
        Esp = registers["Esp"]
            
        #get the debuggee PID
        pid = str(process.get_pid())        

        #prepare the cmdline for getting current handles of the debuggee
        cmdline = "C:\\tools\\sysinternals\\handle.exe -a -p " + pid
        hfound = False
        
        try:
            #execute handle.exe
            handle_process = Popen(cmdline, stdout=PIPE)
            #wait for it to complete
            handle_process.wait()
            #retrieve the output, seperated by new lines
            handle_out =handle_process.communicate()[0].split("\r\n")
            
            #loop through the output line by line, after the program banner
            for x in range(5,len(handle_out)-1):
                #check if the handle value equals the CloseHandle() parameter
                if str(handle) == handle_out[x].partition(":")[0].lstrip():
                    hfound =  True
                    break
        except Exception as e:
            print "Exception while attempting to run handle.exe - %s" % e
        
        #handle is valid, do nothing
        if hfound == True:
            print "Handle found in Debuggee Handle Table"
        #invalid handle
        else:
            print "Handle NOT found in the Debuggee Handle Table"
            print "Program may be attempting to detect presence of debugger"
            print "Skipping function call"
            
            #Clean up the stack
            thread.set_register("Esp", Esp + 8)
            #Set the next instruction to be executed to the return address
            thread.set_register("Eip", return_address)
            #Set the return value to zero
            thread.set_register("Eax", 0x0)
	
	#function for single step exception
	def single_step( self, event ):
			
		print "HELLO!!!!"
		#get process object
		process = event.get_process()
		
		#get thread object
		thread = event.get_thread()
		
		#get the current cpu context
		registers = thread.get_context()
		
		#get the current value of EIP
		Eip = registers["Eip"]
		
		print Eip

		#attempt to dissable the instructions at EIP
		try:
			#dissasemble the instructions at EIP
			disassem = thread.disassemble_instruction(Eip)[2]           
			# mnemonic = disassem.split()[0].strip()
			# operand1 = disassem.split()[1].replace(",","").strip()
			if disassem == "RDTSC":
				#get handle to the main exe module
				main_module = process.get_main_module()
				#calculate the offset from the main module base to the instruction call
				offset = main_module.get_base() - Eip
				print "Timing instruction RDTSC detected at: EIP=%08x  Main_Module_Offset=%08x" % (Eip,offset)
			#check for RDPMC
			if disassem == "RDPMC":
				main_module = process.get_main_module()
				offset = main_module.get_base() - Eip
				print "Timing instruction RDPMC detected at: EIP=%08x  Main_Module_Offset=%08x" % (Eip,offset)
			#check for INT 2ah
			if disassem == "INT 0x2a":
				main_module = process.get_main_module()
				offset = main_module.get_base() - Eip           
				print "Timing instruction INT 0x2a detected at: EIP=%08x  Main_Module_Offset=%08x" % (Eip,offset)
		except:
			pass

	#pre-callback function for GetTickCount()
	def pre_GetTickCount( self, event, return_address):	
		#Timing API notification message
		print "Entering Timing API Call:\n\tGetTickCount()\n\tRA=%08x" % return_address
		
	#post-callback function for GetTickCount()
	def post_GetTickCount( self, event, retval):
		#Timing API notification message
		print "Returning from Timing API Call\n\tGetTickCount()\n\tRV=%d" % retval

#main function for WinAppDbg debugging process
def main_debug( argv ):
	
	filepath = argv

	#create GlobalFlag registry value to disable heap flags used for debugger detection
	Regpath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" 
	Subkey = Regpath + os.path.basename(filepath) 
	hKey = _winreg.CreateKey( _winreg.HKEY_LOCAL_MACHINE, Subkey )
	_winreg.SetValueEx(hKey, "GlobalFlag", 0, REG_SZ, "")
	
	#Enter the debugging process, and pass the EventHandler to the debug object
	with Debug( MyEventHandler(), bKillOnExit = True ) as debug:

        #Start a new process for debugging.
		debug.execl( argv )
	
		#Begin debuggee execution  
		debug.loop()

#call main debugger function with the process name parameter
main_debug(sys.argv[1])