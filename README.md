# HackPCode
Just a self studying note about how to run Ghidra's PCode in python

## Prerequsites
1. [phidra](https://github.com/dod-cyber-crime-center/pyhidra)

## Folders
* ex1: fibonacci calculation in c

## Display PCode in Ghidra
1. Open a binary
1. Go to the panel call **Listing** where the assembly code is shown.
1. At the top-right corner, there is a button call **Edit the Listing Fields** and click it.
1. The button will show another bar of options, choose **Instruction/Data**
1. Another list will display and right click the button named **PCode**.
1. Choose **Enable Field**

## What is P-Code?

P-Code is an intermediate representation (IR) language which is **platform independent**. This platform-independent feature allows it to simulate binaries accross platforms. The IR language converts each instruction into a sequence of P-Code describes how an instruction interacts with the states of a generic purpose processor. 

There are 2 types of P-Code: Raw P-Code and High P-Code. Raw P-Code is regarded as a detailed description about how states are changed step by step when an instruction is executed. High P-Code, on the other hand, is more semantic than Raw P-Code because it is an analyzed result from decompiling. 

The goal of P-Code is to reconstruct the data-flow of a binary regardless of its platform in Ghidra.

## References
1. https://github.com/kohnakagawa/PracticalPCode
1. https://www.youtube.com/watch?v=Qift_6-3y3A
1. Slides of the speaker in the previous link: https://files.brucon.org/2021/brucon2021_slides_gergely_revay.pdf
1. PCode Reference Manual: https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcoderef.html
1. https://github.com/LukeSerne/DecompVis
1. https://research.nccgroup.com/2022/05/20/earlyremoval-in-the-conservatory-with-the-wrench/
1. https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb
1. https://www.cs.virginia.edu/~evans/cs216/guides/x86.html