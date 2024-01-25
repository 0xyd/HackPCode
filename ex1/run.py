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
	emuHelper.writeRegister("RSP", 0x80000000)
	emuHelper.writeRegister("RBP", 0x80000000) 

	## Set up the PC register to decide where 
	## the emulation is going to start
	pcRegister = emuHelper.getPCRegister()
	emuHelper.writeRegister(
		pcRegister, 
		int(f"0x{funcEntry}", 16))

	## Execute emulation
	monitor = ConsoleTaskMonitor()
	controlledReturnAddr = getAddress(program, 0)

	i = 0
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

		## The instruction @ 0x0010118a
		## assigns 0 to the return variable r
		if executionAddress == getAddress(
			program, 
			0x0010118a):
			print(f'Touch addr for initializing return value: {executionAddress}')

		success = emuHelper.step(monitor)
		if not success:
			lastError = emuHelper.getLastError()
			print(f"Emulation error: {lastError}")
			break
		# r = emuHelper.readRegister('RBX')
		# print(f'RBX: {r}')
		i += 1

		if i == 10: break

	r = emuHelper.readMemory(
		getAddress(program, 0x7ffffff0), 4)
	print('r:', r)
	## 
	# r = emuHelper.readRegister('EBX')
	# print(f'EBX: {r}')
	# r = emuHelper.readRegister('EAX')
	# print(f'EAX: {r}')

	print('i:', i)

	## Dispose emulator
	emuHelper.dispose()
	
