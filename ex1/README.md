# Example 1: A fibonacci

## Goal

We want to overwrite the hardcoded value *n = 10* to *n = 15* in the *main.c* so that the calculation result of *r* changes to *610* (Original *r* is *55*).

## HOW TO

In the beginning, we will need to set the entry point for the emulation and initialize an `EmulatorHelper`.
```python
funcEntry = getSymbolAddress(program, 'main')
emuHelper = EmulatorHelper(program)
```

Next, we have to setup the stack and base registers because the default value for registers are 0 which will lead to the failure of emulation. The register values are flexible.
```python
emuHelper.writeRegister("RSP", 0x40000000)
emuHelper.writeRegister("RBP", 0x40000000) 
```

Before emulation, we have to set the PC register to tell Ghidra where to start and set the ending address for emulation. We select main's entry point as the starting and address `0x0010119e` as the ending point. The address `0x0010119e` is the instruction occured after fibbonacci is finish. (But the address `0x0` shall work.)
```python
pcRegister = emuHelper.getPCRegister()
emuHelper.writeRegister(
	pcRegister, 
	int(f"0x{funcEntry}", 16))
controlledReturnAddr = getAddress(
	program, 
	0x0010119e)
```  

We use `ConsoleTaskMonitor()` to control the `EmulatorHelper` by `step(...)`. Doing so, we can record what instructions (`getExecutionAddress()`) are executed during emulation. We use the address of instruction to justify if the condition of termination is satisfied.
```python
monitor = ConsoleTaskMonitor()

while monitor.isCancelled() is False:

	executionAddress = emuHelper.getExecutionAddress()

	if executionAddress == controlledReturnAddr:
		break

	...

	success = emuHelper.step(monitor)
	if not success:
		lastError = emuHelper.getLastError()
		print(f"Emulation error: {lastError}")
		break


```

The rest about how to manipulate memory to achieve the goal can be found in `run.py`.