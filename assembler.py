from os import write


source = """
mov al, byte 5
.Label
	mov eax, al
	add eax, byte 5
	jmp .Label
.String
	db "test", 0
hlt
"""

OP_ARGS_COUNT_MAP = {
	"mov": 2,
	"add": 2,
	"jmp": 1,
	"hlt": 0,
	"db": 2,
	"dw": 2
}

OP_BIN = {
	#inst => ([6:7] args count, [0:5] opcode)
	"mov": 0b10000000,
	"add": 0b10000001,
	"jmp": 0b01000010,
	"hlt": 0b00000011
}

REG_IDX_MAP = {
	"ax": 0,
	"al": 0,
	"ah": 1,
	"bx": 2,
	"bl": 2,
	"bh": 3,
	"eax": 4
}

#arg => ([:1] arg size)
#arg sizes:
#0 - byte
#1 - word (2 bytes)

class Assembly(object):
	def __init__(self):
		self.labels = {}
		self.instructions = []
		self.size = 0
		self.binary = ""

class Instruction(object):
	def __init__(self, op, args):
		self.op = op
		self.args = args

	def __repr__(self):
		return f"([{self.op}] {' '.join(self.args)})"

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

	for line in lines:
		if line[0] == '.':
			assembly.labels[line] = assembly.size
			continue

		firstSpace = line.find(' ')
		if firstSpace != -1:
			op = line[:firstSpace]
			args = [x for x in line[firstSpace:].split(',') if x != ' ']
		else:
			op = line
			args = []

		for idx, arg in enumerate(args):
			args[idx] = arg.replace(' ', '')
		inst = Instruction(op, args)
		assembly.instructions.append(inst)
		assembly.size += OP_ARGS_COUNT_MAP[inst.op] + 1

	binary = ""

	for idx, inst in enumerate(assembly.instructions):
		if inst.op == "db":
			string = inst.args[0].replace('"', '')
			for char in string:
				binary += char
			binary += chr(int(inst.args[1]))
			continue

		opcode = OP_BIN[inst.op]
		assembly.instructions[idx].op = str(opcode)
		for idx, arg in enumerate(inst.args):
			if arg[0] == '.':
				labelAddr = assembly.labels[arg]

				inst.args[idx] = str(labelAddr + 0b00000000)
			elif arg in REG_IDX_MAP.keys():
				inst.args[idx] = str(REG_IDX_MAP[arg] + 0b00000000)
			elif arg.startswith("byte"):
				val = int(arg.replace("byte", ''))
				inst.args[idx] = str(val + 0b00000000)
			elif arg.startswith("word"):
				val = int(arg.replace("word", ''))
				inst.args[idx] = str(val + 0b10000000)
		
		instStr = chr(int(inst.op)) + "".join([chr(int(x)) for x in inst.args])
		binary += instStr

	write_to_file(binary, "out.bin")
	return binary

if __name__ == '__main__':
	res = assemble(source)
	print(res)