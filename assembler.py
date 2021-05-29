source = """
const CONST_VAL byte 0x4 ;define constant value of 4
db "test"
db "test", 0x5
db 6, 7
dw 0x8
resb 7
resw 2
.Label
	add ax, word [.Data]
	sys 0x1
	jmp .Label
.String
	db "test", 0x0
.Data
	dw 0x1
.EmptySpace
	resb 10
"""
# output: b"\xc2\x80@\x05\xc2\x80D@\xc2\x81D\xc2\x85B\x03test\x00B\x10E\x03\x04\xc2\x80D\x0b\x08G\x15\x03"

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
	"dw",
	"resb",
	"resw",
	"const"
]

ARG_TYPE_BYTE = 0
ARG_TYPE_WORD = 16384

ARG_TYPE_ADDRESS = 0
ARG_TYPE_VALUE = 32768

class Assembly(object):
	def __init__(self):
		self.labels = {}
		self.constants = {}
		self.binary = ""
		self.size = 0
		self.instructions = []

class Instruction(object):
	def __init__(self):
		self.address = 0
		self.operation = None
		self.args = []

	def __repr__(self):
		return f"{hex(self.address)}: {self.operation.upper()} [{', '.join(self.args)}]"

class Directive(object):
	def __init__(self):
		self.representation = ""
	
	def __repr__(self):
		return f"DIRECTIVE bytesize: {len(self.representation)} value: {self.representation}"

class Argument(object):
	def __init__(self):
		self.type = None
		self.value = None

	def __repr__(self):
		return f"{self.type}:{self.value}"

class CompilerError(Exception):
	def __init__(self, msg, inst_num: int):
		super().__init__(f"Error occured at instruction {inst_num}: {msg}")

class ArgType:
	Byte = "BYTE"
	Word = "WORD"

def try_convert_to_int(string):
	try:
		return int(string, 0)
	except Exception:
		return None

def handle_directive(line, line_idx, assembly):
	directive = Directive()
	
	dir = line.split(' ')[0]

	if dir == "const":
		args = line.split(' ')[1:]
		args = [arg for arg in args if arg != '']
		if len(args) != 3:
			raise CompilerError(f"Invalid arguments count for const directive: {len(args)}", line_idx)
		
		value = try_convert_to_int(args[-1])
		if value is None:
			value = ord(args[-1])

		if args[1] == "byte":
			value += ARG_TYPE_BYTE
		elif args[1] == "word":
			value += ARG_TYPE_WORD
		else:
			raise CompilerError(f"Invalid const value type '{args[2]}'", line_idx)

		assembly.constants[args[0]] = value
	elif dir == "db":
		args = line.split(' ')
		if len(args) < 2:
			raise CompilerError(f"Didn't specify arguments for define byte directive.", line_idx)
		
		args = [x.replace(',', '') for x in args[1:]]

		for arg in args:
			value = try_convert_to_int(arg)
			if value is None: #means we have string here so we trim every byte and append it to repr
				arg = arg.replace('"', '')
				for char in arg:
					directive.representation += chr(ord(char) & 0xff) #we mask it to get only lower part as we define byte not word
			else: #means we encountered int written as string so we decode it as a raw byte
				directive.representation += chr(value & 0xff)
	elif dir == "dw":
		args = line.split(' ')
		if len(args) < 2:
			raise CompilerError(f"Didn't specify arguments for define word directive.", line_idx)
		
		args = args[1].split(',')
		
		for arg in args:
			value = try_convert_to_int(arg)
			if value is None:
				raise CompilerError(f"Define byte directive doesn't accept strings as input.", line_idx)
			
			directive.representation += chr(value >> 8) + chr(value & 0xff) #we separate upper and lower part of word and save them as separate bytes
	elif dir == "resb":
		args = line.split(' ')
		if len(args) < 2:
			raise CompilerError(f"Didn't specify arguments for reserve byte directive.", line_idx)
		
		count = try_convert_to_int(args[1])
		if count is None:
			raise CompilerError(f"Invalid argument for reserve byte directive: '{args[1]}'", line_idx)
		directive.representation += '\0' * count
	elif dir == "resw":
		args = line.split(' ')
		if len(args) < 2:
			raise CompilerError(f"Didn't specify arguments for reserve word directive.", line_idx)
		
		count = try_convert_to_int(args[1])
		directive.representation += "\0\0" * count
	
	assembly.size += len(directive.representation)

	return directive

def handle_label(line, assembly):
	label_name = line.replace('.', '')
	assembly.labels[label_name] = assembly.size

	return Directive()

def handle_instruction(line, line_idx, assembly):
	return None

def prepare_source(text):
	new_lines = []

	for l in [x for x in text.split('\n') if x != '']:
		l = l.replace('\t', '')
		if l.find(';') != -1:
			l = l.split(';')[0]
		
		new_lines.append(l)
	
	return new_lines

def parse(assembly):
	for idx, l in enumerate(assembly.instructions):
		line_start = l.split(' ')[0]
		if line_start in DIRECTIVES: #handle preprocessor directive
			content = handle_directive(l, idx, assembly)
		elif line_start in OPERATIONS: #create instruction to be translated into machine code
			content = handle_instruction(l, idx, assembly)
		elif line_start.startswith('.'): #use different function for label creation as it is not actually a directive in any meaning
			content = handle_label(l, assembly)
		else:
			raise CompilerError(f"Invalid instruction or compiler directive: '{line_start}'", idx)
		
		assembly.instructions[idx] = content

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

	assembly.instructions = prepare_source(source)
	
	parse(assembly)
	
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