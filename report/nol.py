import sys

if len(sys.argv) > 1:
    try:
        f = open(sys.argv[1], "r")
    except FileNotFoundError:
        print("Error: %s - file not found." % sys.argv[1])
        sys.exit(1)
else:
    f = sys.stdin

char = f.read(1)
lines = 0

while char != '':
    if char == '\n':
        lines += 1
    char = f.read(1)

print("Number of lines: %d" % lines);
sys.exit(0)

