source = """
const CNST, word 64
mov al, byte 5
.Label
	mov eax, al
	add eax, word 5
	jmp .Label
.String
	db "test", 0
jmp $
jeq .Label
.Func
	mov eax, [.Number]
	and CNST			; this is a comment
	nop
	ret
call .Func
.Number
	db 0x01
hlt
"""
# output: b"\xc2\x80@\x05\xc2\x80D@\xc2\x81D\xc2\x85B\x03test\x00B\x10E\x03\x04\xc2\x80D\x0b\x08G\x15\x03"

# bits numeration:
# most significant bit - 0
#
# instruction structure:
# op [arg, ...]
#
# operation structure:
# size: 1 byte
# 0b00000000
# bits:
# 2 - 8 => opcode
# 0 - 2 => args count
#
# preprocessor directive structure:
# keyword [arg, ...]
#
# preprocessor keywords:
# db [*byte, optional:termination_character]: define bytes
# const [name, type value]: define constant
#
# types:
# byte - 8 bits
# word - 16 bits
#
# address size: word
#
# reserved address values:
# 0x0 -> accumulator
# 0x2 -> base pointer
# 0x4 -> stack pointer
# 0x6 -> stack base pointer (always equal to 0xa)
# 0x8 -> flags register
# 0xa - 0x40a -> stack (1 kb)
#
# base program address: 0x40c (just after end of stack)
# 
# address wildcard character: $
# expands to address of used instruction
# example:
# 0x00 jmp $     is the same as
# 0x00 jmp 0x00
#
# value at address argument: [address]
# expands to the value found at given address
# example:
# 0x00 "h"
# 0x01 mov eax, [0x00]   is the same as
# 0x00 "h"
# 0x01 mov eax, "h"
#
# label structure:
# .[label_name]
# expands to address of next instruction
# 
# argument structure:
# [type, value]
#
# value structure:
# 0b00...
# bits:
# 0 => is value or address (1 if value)
# 1 => argument type (0 for byte, 1 for word)
# 2 - n => value
#
# comment structure:
# ;[comment]
#
# register size: word
#
# registers literals:
# ax - acummulator
# bx - base register
# sp - stack pointer register
# bp - stack base pointer register
# 
# x replacements:
# l - register's lower byte
# h - register's higher byte
#
# flags register structure:
# 0b0000000000000000 (word)
# bits:
# 0 => zero flag (set if operation result is 0)
# 1 => sign flag (set if operation result is negative)
# 2 => parity flag (set if operation result is a multiple of 2)
# 3 => carry flag (set if addition result overflows register or subtraction result is negative)
# 4 => interruption flag (set if interrupts are enabled)
# 5 => overflow flag (set if operation overflows register)
# 6 => stack overflow flag (set if push* operation causes stack overflow)
# 7 - 16 => unused
#
# operations list:
# add - add and store in ax, args: [register or value, register or value]
# adc - add with carry and store in ax, args: same as add
# div - divide and store in ax, args: same as adc
# mul - multiply and store in ax, args: same as div
# sub - subtract and store in ax, args: same as mul
# sbb - subtract with borrow and store in ax, args: same as sub
# and - logical AND ax with value and store in ax, args: [value]
# or  - logical OR ax with value and store in ax, same as and
# xor - logical XOR ax with value and store in ax, same as or
# sl - shift ax left and store in ax, args: same as xor
# sr - shift ax right and store in ax, args: same as sl
# not - logical NOT of ax and store in ax, args: None
# call - call procedure and put address of next instruction on stack, args: [procedure address]
# ret - return from procedure and pop address of next instruction after call from stack, args: None
# sys - call a syscall, args: [syscall index]
# inc - increment by one, args: [register]
# dec - decrement by one, args: [register]
# hlt - stop processor, args: None
# int - call interupt, args: [interrupt index]
# jmp - jump to address, args [address]
# jeq - jump to address if zero flag set, args: same as jmp
# jne - jump to address if zero flag not set, args: same as jeq
# mov - move address to certain location to another, args: [register or memory address, register or memory address]
# nop - no operation, args: None
# pop - pop data from stack, args: None
# push - push data onto stack, args: [value]
# test - logical AND and set zero flag if not equal, args: [value or register, value or register]

OPERATIONS = {
	"add":  0b10000000,
	"adc":  0b10000001,
	"div":  0b10000010,
	"mul":  0b10000011,
	"sub":  0b10000100,
	"sbb":  0b10000101,
	"and":  0b01000110,
	"or":   0b01000111,
	"xor":  0b01001000,
	"sl":   0b01001001,
	"sr":   0b01001010,
	"not":  0b00001011,
	"call": 0b01001100,
	"ret":  0b00001101,
	"sys":  0b01001110,
	"inc":  0b01001111,
	"dec":  0b01010000,
	"hlt":  0b00010001,
	"int":  0b01010010,
	"jmp":  0b01010011,
	"jeq":  0b01010100,
	"jne":  0b01010101,
	"mov":  0b10010110,
	"nop":  0b00010111,
	"pop":  0b00011000,
	"push": 0b01011001,
	"test": 0b10011010
}

DIRECTIVES = [
	"db",
	"const"
]

ARG_TYPE_BYTE = 0b00000000
ARG_TYPE_WORD = 0b10000000

class Assembly(object):
	def __init__(self):
		self.labels = {}
		self.constants = {}
		self.line_addresses = [0,]
		self.binary = ""
		self.size = 0

class CompilerError(Exception):
	def __init__(self, msg):
		super().__init__(msg)

def create_lines(text):
	lines = [x for x in text.split('\n') if x != '']
	newLines = []

	for l in lines:
		formatted = l.replace('\t', '')
		if formatted.find(';') != -1:
			formatted = formatted.split(';')[0]
		newLines.append(formatted)

	return newLines

def handle_preprocessor_directive(line, assembly):
	if line.startswith("db"):
		line = line.replace("db", '')
		line = line.replace(' ', '')
		
		args = line.split(',')
		if len(args) not in [1, 2]:
			raise CompilerError(f"Preprocessor error: Invalid 'db' args count: {len(args)}")
		
		if args[0].find('"') != -1:
			new_line = args[0].replace('"', '')
		else:
			new_line = chr(int(args[0]))
		if len(args) == 2:
			new_line += chr(int(args[1]))

		assembly.line_addresses.append(len(new_line))
		return new_line
	elif line.startswith("const"):
		line = line.replace("const", '')
		line = line.replace(' ', '')
		
		args = line.split(',')
		if len(args) != 2:
			raise CompilerError(f"Preprocessor error: Invalid 'const' args count: {len(args)}")

		if args[1].startswith("byte"):
			arg = args[1].replace("byte", '')
			arg = int(arg) + ARG_TYPE_BYTE
		elif args[1].startswith("word"):
			arg = args[1].replace("word", '')
			arg = int(arg) + ARG_TYPE_WORD
		else:
			raise CompilerError(f"Preprocessor error: invalid type of argument: '{args[1]}'")

		const_name = args[0]
		const_value = arg

		assembly.constants[const_name] = const_value

	return None

def assemble(source):
	assembly = Assembly()
	lines = create_lines(source)
	
	for idx, line in enumerate(lines):
		l = handle_preprocessor_directive(line, assembly)
		if l:
			lines[idx] = l
			continue
	
	return assembly


class DBDirective(object):
	def __init__(self, text, term_char):
		self.text = text
		self.term_char = term_char
	
	def __repr__(self):
		return f"[db] ({self.text}, {self.term_char})"

class Assembly_OLD(object):
	def __init__(self):
		self.labels = {}
		self.instructions = []
		self.size = 0
		self.binary = ""

class Instruction(object):
	def __init__(self, op, args, addr):
		self.op = op
		self.args = args
		self.addr = addr

	def __repr__(self):
		return f"[{self.op}] ({', '.join([str(x) for x in self.args])})"



REG_INDICES = {
	"ax": 0,
	"al": 0,
	"ah": 1,
	"bx": 2,
	"bl": 2,
	"bh": 3,
	"eax": 4
}

DIRECTIVES = [
	"db"
]

ARG_TYPE_BYTE = 0b00000000
ARG_TYPE_WORD = 0b10000000

ARGS_COUNT_MASK = 0b00000110
ARG_REGISTER_IDX_MASK = 0b01000000

def split(text):
	lines = [x for x in text.split('\n') if x != '']
	newLines = []

	for l in lines:
		formatted = l.replace('\t', '')
		newLines.append(formatted)

	return newLines

def write_to_file(text, filename):
	with open(filename, "wb") as f:
		f.write(text.encode("UTF-8"))

def assemble_old(text):
	assembly = Assembly()

	lines = split(text)
	curr_addr = 0

	for line in lines:
		if line.startswith('.'):
			assembly.labels[line] = curr_addr
			continue
		
		firstSpaceIdx = line.find(' ')
		if firstSpaceIdx != -1:
			opcode = line[:firstSpaceIdx]
		else:
			opcode = line
		args = line[firstSpaceIdx:].replace(' ', '').split(',')

		if firstSpaceIdx == 2:
			#directives
			if opcode == "db":
				string = args[0].replace('"', '')
				assembly.instructions.append(DBDirective(string, chr(int(args[1]))))
				curr_addr += len(string) + 1
		elif firstSpaceIdx == 3:
			#operations
			if opcode in OPERATIONS.keys():
				op = OPERATIONS[opcode]
				assembly.instructions.append(Instruction(op, args, curr_addr))
				curr_addr += 1 + (op.opcode >> ARGS_COUNT_MASK)
		else:
			#operations (0 arguments)
			op = OPERATIONS[opcode]
			assembly.instructions.append(Instruction(op, [], curr_addr))
			curr_addr += 1

	for inst in assembly.instructions:
		if isinstance(inst, DBDirective):
			assembly.size += len(inst.text) + 1
			continue

		for idx, arg in enumerate(inst.args):
			if arg.startswith('.'):
				labelAddr = assembly.labels[arg]
				inst.args[idx] = int(labelAddr + 0b00000000)
			elif arg == '$':
				inst.args[idx] = int(inst.addr)
			elif arg in REG_INDICES.keys():
				inst.args[idx] = int(REG_INDICES[arg] + ARG_REGISTER_IDX_MASK)
			elif arg.startswith("byte"):
				inst.args[idx] = int(arg.replace("byte", '')) + ARG_TYPE_BYTE
			elif arg.startswith("word"):
				inst.args[idx] = int(arg.replace("word", '')) + ARG_TYPE_WORD
			
		assembly.size += 1 + (inst.op.opcode >> ARGS_COUNT_MASK)
		
	for inst in assembly.instructions:
		if isinstance(inst, DBDirective):
			assembly.binary += inst.text
			assembly.binary += inst.term_char
			continue
		
		assembly.binary += chr(inst.op.opcode)
		for arg in inst.args:
			assembly.binary += chr(arg)

	return assembly

if __name__ == '__main__':
	res = assemble(source)
	print(res.binary.encode("utf-8"))