with open("fff", 'rt') as ffile:
    data = ffile.read()

print("BYTE KDDriverData[] = {")
for cc, num in enumerate(data.split(" ")):
    print("0x" + num + ", ", end="")
    if cc % 40 == 0:
        print("\n")
print("};")