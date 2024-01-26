import pyhidra
pyhidra.start()

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

def getAddress(program, offset):
	return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getSymbolAddress(program, symbolName):
	symbol = SymbolUtilities.getLabelOrFunctionSymbol(
		program, 
		symbolName, 
		None)
	if (symbol != None):
		return symbol.getAddress()
	else:
		raise("Failed to locate label: {}".format(symbolName))

def getProgramRegisterList(program):
	pc = program.getProgramContext()
	return pc.registers

with pyhidra.open_program('main.o') as flatApi:
	
	program = flatApi.getCurrentProgram()
	funcManager = program.getFunctionManager()
	for f in funcManager.getFunctions(True):
		fname = f.getName()
		memView = f.getBody()
		# if fname == 'fibbonacci':
		if fname == 'main':
			print(fname)
			print(memView.getMinAddress())
			print(memView.getMaxAddress())

			# List 
			print(f.getLocalVariables())

	funcEntry = getSymbolAddress(program, 'main')
	print('funcEntry:', funcEntry)
	# funcEntry = getSymbolAddress(program, 'fibbonacci')

	## Initialize emulator for P-Code emulation
	emuHelper = EmulatorHelper(program)

	## Set up the registers for the function call;
	## RBP and RSP are registers for the stackframe and
	## RBX is register for function's argument.
	
	## This setup can emulate the whole code...
	emuHelper.writeRegister("RSP", 0x40000000)
	emuHelper.writeRegister("RBP", 0x40000000) 

	## Set up the PC register to decide where 
	## the emulation is going to start
	pcRegister = emuHelper.getPCRegister()
	emuHelper.writeRegister(
		pcRegister, 
		int(f"0x{funcEntry}", 16))

	## Execute emulation
	monitor = ConsoleTaskMonitor()
	controlledReturnAddr = getAddress(
		program, 
		0x0010119e)
	# controlledReturnAddr = getAddress(program, 0)

	i = 0
	prevExecution = None
	local10Addr = None # Addr stores argument value of fibonacci
	localcAddr  = None # Addr stores return value of fibonacci
	while monitor.isCancelled() is False:
		executionAddress = emuHelper.getExecutionAddress()
		print('-' * 10)
		print(f'i: {i}, {executionAddress}')
		r = emuHelper.readRegister('RBP')
		print(f'RBP: {hex(int(r.toString()))}')
		r = emuHelper.readRegister('RSP')
		print(f'RSP: {hex(int(r.toString()))}')
		### When instruction reaches RET in fibonacci
		### it ends.
		if executionAddress == controlledReturnAddr:
		# if executionAddress.toString() == "0010119b":
			break

		## The instruction @ 0x00101183 
		## assigns the value for fibonacci
		if executionAddress == getAddress(
			program, 0x00101183):
			print(f'Touch addr for assigning fibonacci value: {executionAddress}')
			## Ghidra says local_10 is RBP-0x8 
			rbpAddr = emuHelper.readRegister('RBP')

			# print(rbpAddr)
			# print('type(rbpAddr):', type(rbpAddr))
			# print(dir(rbpAddr))
			# print('rbpAddr.longValue:', rbpAddr.longValue())
			# print('rbpAddr.intValue:', rbpAddr.intValue())
			local10Addr = getAddress(
				program, 
				rbpAddr.intValue() - 0x8)
			print(f'Addr in RBP: {hex(rbpAddr.intValue())}')
			print(f'local10Addr: {local10Addr}')

		## Overwrite the assigned value
		if prevExecution == getAddress(
			program, 0x00101183):
			r = emuHelper.readMemoryByte(local10Addr)
			# r = emuHelper.readMemory(local10Addr, 4) ## Don't know why it doesn't work
			print(f'Read the value in addr of local_10 ({local10Addr}): {r}')
			emuHelper.writeMemory(
				local10Addr,
				(15).to_bytes(
					length=4, 
					byteorder='little')
				)
			r = emuHelper.readMemoryByte(local10Addr)
			print(f'Read the value in addr of local_10 after overwritten ({local10Addr}): {r}')

		## The instruction @ 0x0010118a
		## assigns 0 to the return variable r
		if executionAddress == getAddress(
			program, 
			0x0010118a):
			print(f'Touch addr for initializing return value: {executionAddress}')
			## Ghidra says local_c is RBP-0x4 
			rbpAddr = emuHelper.readRegister('RBP')
			localcAddr = getAddress(
				program, 
				rbpAddr.intValue() - 0x4)
			print(f'Addr in RBP: {hex(rbpAddr.intValue())}')
			print(f'localcAddr: {localcAddr}')

		success = emuHelper.step(monitor)
		if not success:
			lastError = emuHelper.getLastError()
			print(f"Emulation error: {lastError}")
			break
		i += 1
		prevExecution = executionAddress

		### This is temp
		# if i == 10: break

	## Let's read the return value here
	print(f'Total number of executed instructions {i}')
	r = emuHelper.readMemory(localcAddr, 4)
	import struct
	print(struct.unpack('<I', r))
	print(dir(r))

	## Dispose emulator
	emuHelper.dispose()
	
