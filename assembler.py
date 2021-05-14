source = """
mov al, byte 5
.Label
	mov eax, al
	add eax, word 5
	jmp .Label
.String
	db "test", 0
jmp $
hlt
"""

class Operation(object):
	"""
	    10      000001 (1 byte)
	    ^^      ^^^^^^
	args count  opcode
	"""
	def __init__(self, mnemonic, opcode):
		self.mnemonic = mnemonic
		self.opcode = opcode
	
	def __repr__(self):
		return f"{self.mnemonic}"

class DBDirective(object):
	def __init__(self, text, term_char):
		self.text = text
		self.term_char = term_char
	
	def __repr__(self):
		return f"[db] ({self.text}, {self.term_char})"

class Assembly(object):
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

OPERATIONS = {
	"mov": Operation("mov", 0b10000000),
	"add": Operation("add", 0b10000001),
	"jmp": Operation("jmp", 0b01000010),
	"hlt": Operation("hlt", 0b00000011),
	"int": Operation("int", 0b00000100),
	"jeq": Operation("jeq", 0b01000101),
	"jne": Operation("jne", 0b01000110),
	"cal": Operation("cal", 0b01000111),
	"ret": Operation("ret", 0b00001000)
}

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

def assemble(text):
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
	print(res.binary)