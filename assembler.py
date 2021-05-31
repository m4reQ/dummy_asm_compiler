source = """
const CONST_VAL byte 0x4 ;define constant value of 4
db "test"
db "test", 0x5
db 6, 7
dw 0x8
resb 7
resw 2
jmp $
push word 500 ;push 500 as a word onto the stack
pop byte 2
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

OPERATIONS = {
	"add":   0b10000000,
	"adc":   0b10000001,
	"div":   0b10000010,
	"mul":   0b10000011,
	"sub":   0b10000100,
	"sbb":   0b10000101,
	"and":   0b01000110,
	"or":    0b01000111,
	"xor":   0b01001000,
	"sl":    0b01001001,
	"sr":    0b01001010,
	"not":   0b00001011,
	"call":  0b01001100,
	"ret":   0b00001101,
	"sys":   0b01001110,
	"inc":   0b01001111,
	"dec":   0b01010000,
	"hlt":   0b00010001,
	"int":   0b01010010,
	"jmp":   0b01010011,
	"jeq":   0b01010100,
	"jne":   0b01010101,
	"mov":   0b10010110,
	"nop":   0b00010111,
	"pop":   0b01011000,
	"push":  0b01011001,
	"pushf": 0b00011010,
	"popf":  0b00011011,
	"test":  0b10011100
}

NON_TYPED_OPERATIONS = [
	"jmp",
	"jeq",
	"jne"
]

DIRECTIVES = [
	"db",
	"dw",
	"resb",
	"resw",
	"const"
]

REGISTER_LITERALS = {
	"ax": 0x0,
	"al": 0x0,
	"ah": 0x1,
	"bx": 0x2,
	"bl": 0x2,
	"bh": 0x3,
	"cx": 0x4,
	"cl": 0x4,
	"ch": 0x5,
	"dx": 0x6,
	"dl": 0x6,
	"dh": 0x7,
	"sp": 0x8,
	"bp": 0xa
}

ARG_TYPE_BYTE = 0
ARG_TYPE_WORD = 16384

ARG_TYPE_ADDRESS = 0
ARG_TYPE_VALUE = 32768

ARGS_COUNT_MASK = 0b11000000

INDIRECT_MODE_MASK = 0b00100000

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
		self.operation = ""
		self.opcode = 0b0
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
		assembly.size += count
	elif dir == "resw":
		args = line.split(' ')
		if len(args) < 2:
			raise CompilerError(f"Didn't specify arguments for reserve word directive.", line_idx)
		
		count = try_convert_to_int(args[1])
		if count is None:
			raise CompilerError(f"Invalid argument for reserve word directive: '{args[1]}'", line_idx)
		assembly.size += count * 2
	
	assembly.size += len(directive.representation)

	return directive

def handle_label(line, assembly):
	label_name = line.replace('.', '')
	assembly.labels[label_name] = assembly.size

	return Directive()

def handle_instruction(line, line_idx, assembly):
	mnemonic = line.split(' ')[0]
	opcode = OPERATIONS[mnemonic]
	args = line.replace(mnemonic, '').replace(' ', '').split(',')

	args_count = (opcode & ARGS_COUNT_MASK) >> 6
	if len(args) != args_count:
		raise CompilerError(f"Invalid args count for operation '{mnemonic}': {len(args)}", line_idx)
	
	inst = Instruction()
	inst.address = assembly.size
	inst.operation = mnemonic
	inst.opcode = opcode

	for arg in args:
		parse_arg(arg, line_idx, inst, assembly)
	
	return inst

def parse_arg(arg, line_idx, inst, assembly):
	arg_i = Argument()

	is_address = False

	if arg.startswith("byte"):
		arg_i.type = ArgType.Byte
	elif arg.startswith("word"):
		arg_i.type = ArgType.Word
	else:
		is_address = True
	
	if arg_i.type and inst.operation in NON_TYPED_OPERATIONS: #check if operation is non typed
		raise CompilerError(f"{inst.operation} is not typed, but the agument type was specified.", line_idx)
	
	if is_address:
		inst.opcode += INDIRECT_MODE_MASK
	
	arg = arg.replace(arg_type, '')

	if arg == "$": #first check if arg is a wildcard address character
		value = inst.address
	elif arg.startswith('.'): #check if argument is a label and get memory address of that label
		if arg not in assembly.labels:
			raise CompilerError(f"Invalid label name: '{arg.replace('.', '')}'", line_idx)
	
	inst.args.append(arg_i)

	#add ax, word [.Data]

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

def write_to_file(text, filename):
	with open(filename, "wb") as f:
		f.write(text.encode("UTF-8"))

def assemble(source):
	assembly = Assembly()

	assembly.instructions = prepare_source(source)
	
	parse(assembly)
	
	return assembly

if __name__ == '__main__':
	res = assemble(source)
